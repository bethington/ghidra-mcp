"""
Fun-Doc Web Dashboard: Real-time control panel for RE documentation progress.

Features:
- WebSocket push updates via Flask-SocketIO (no page reloading)
- Live activity feed: tool calls, model text, score updates streaming
- Deduction breakdown: where are the points hiding?
- ROI-ranked work queue with pin/skip controls
- Scan triggers: rescan all or per-binary from the dashboard
- Run log stats: model performance, stuck functions
"""

import json
import threading
from collections import defaultdict
from datetime import datetime
from pathlib import Path

from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit as sio_emit

from event_bus import get_bus

import uuid


class WorkerManager:
    """Manages concurrent documentation worker threads (max 3)."""

    MAX_WORKERS = 4

    def __init__(self, state_file, bus, socketio):
        self._workers = {}
        self._lock = threading.Lock()
        self._state_file = state_file
        self._bus = bus
        self._socketio = socketio
        self._in_progress_keys = set()

    def start_worker(self, provider="claude", count=5, model=None, binary=None, continuous=False):
        with self._lock:
            active = {wid: w for wid, w in self._workers.items() if w["status"] in ("starting", "running", "stopping")}
            if len(active) >= self.MAX_WORKERS:
                active_info = ", ".join(f"{w['provider']}#{wid}({w['status']})" for wid, w in active.items())
                raise ValueError(f"Maximum {self.MAX_WORKERS} workers ({len(active)} active: {active_info})")

            worker_id = str(uuid.uuid4())[:8]
            stop_flag = threading.Event()
            worker = {
                "id": worker_id, "provider": provider, "count": count,
                "continuous": continuous,
                "model": model, "binary": binary, "thread": None,
                "stop_flag": stop_flag, "started_at": datetime.now().isoformat(),
                "status": "starting",
                "progress": {"completed": 0, "skipped": 0, "failed": 0, "current": None},
            }
            self._workers[worker_id] = worker

        thread = threading.Thread(target=self._run_worker, args=(worker_id,), daemon=True)
        worker["thread"] = thread
        thread.start()
        self._emit_status()
        return worker_id

    def stop_worker(self, worker_id):
        with self._lock:
            worker = self._workers.get(worker_id)
            if not worker:
                raise ValueError(f"Unknown worker: {worker_id}")
            worker["stop_flag"].set()
            worker["status"] = "stopping"
        self._emit_status()

    def get_status(self):
        with self._lock:
            # Prune workers finished > 5 minutes ago
            now = datetime.now()
            stale = [
                wid for wid, w in self._workers.items()
                if w["status"] in ("finished", "stopped")
                and (now - datetime.fromisoformat(w.get("finished_at", w["started_at"]))).total_seconds() > 300
            ]
            for wid in stale:
                del self._workers[wid]

            return [
                {
                    "id": w["id"], "provider": w["provider"], "count": w["count"],
                    "continuous": w.get("continuous", False),
                    "model": w["model"], "binary": w["binary"], "status": w["status"],
                    "progress": dict(w["progress"]), "started_at": w["started_at"],
                }
                for w in self._workers.values()
            ]

    def _run_worker(self, worker_id):
        """Worker loop — fetches one function at a time to avoid conflicts with other workers."""
        from event_bus import set_worker_id
        set_worker_id(worker_id)  # Tag all events from this thread

        worker = self._workers[worker_id]
        current_key = None
        try:
            from fun_doc import (
                load_state, save_state, get_next_functions,
                start_session, end_session, process_function,
            )

            worker["status"] = "running"
            self._emit_status()
            self._bus.emit("worker_started", {
                "worker_id": worker_id, "provider": worker["provider"], "count": worker["count"],
            })

            state = load_state()
            original_binary = state.get("active_binary")
            if worker["binary"]:
                state["active_binary"] = worker["binary"]

            session = start_session(state)
            processed = 0

            while not worker["stop_flag"].is_set() and (worker["continuous"] or processed < worker["count"]):
                # Reload state each iteration to get fresh scores/queue
                state = load_state()
                if worker["binary"]:
                    state["active_binary"] = worker["binary"]

                # Get next function, skipping ones already in progress
                candidates = get_next_functions(state, count=10)
                target = None
                with self._lock:
                    for k, f in candidates:
                        if k not in self._in_progress_keys:
                            self._in_progress_keys.add(k)
                            target = (k, f)
                            current_key = k
                            break

                if target is None:
                    break  # No more work available

                key, func = target
                worker["progress"]["current"] = {"key": key, "name": func.get("name", "?"), "address": func.get("address", "?")}
                self._emit_status()
                self._bus.emit("worker_progress", {
                    "worker_id": worker_id, "current": worker["progress"]["current"],
                    "completed": worker["progress"]["completed"], "total": worker["count"],
                })

                result = process_function(
                    key, func, state, model=worker["model"],
                    provider=worker["provider"], stop_flag=worker["stop_flag"],
                )

                # Release the key immediately after processing
                with self._lock:
                    self._in_progress_keys.discard(key)
                    current_key = None

                processed += 1
                if result in ("quit", "stopped"):
                    break
                elif result == "completed":
                    worker["progress"]["completed"] += 1
                    session["completed"] += 1
                    session["functions"].append(key)
                elif result == "skipped":
                    worker["progress"]["skipped"] += 1
                    session["skipped"] += 1
                elif result in ("failed", "blocked", "needs_redo"):
                    worker["progress"]["failed"] += 1
                    session["failed"] += 1

                self._emit_status()

            end_session(state)
            if worker["binary"] and original_binary != worker["binary"]:
                if original_binary:
                    state["active_binary"] = original_binary
                else:
                    state.pop("active_binary", None)
            save_state(state)

        except Exception as e:
            self._bus.emit("worker_stopped", {"worker_id": worker_id, "reason": f"error: {e}"})
        finally:
            worker["status"] = "finished" if not worker["stop_flag"].is_set() else "stopped"
            worker["finished_at"] = datetime.now().isoformat()
            worker["progress"]["current"] = None
            with self._lock:
                if current_key:
                    self._in_progress_keys.discard(current_key)
            self._emit_status()
            self._bus.emit("worker_stopped", {
                "worker_id": worker_id, "reason": worker["status"],
                "progress": dict(worker["progress"]),
            })

    def _emit_status(self):
        self._socketio.emit("worker_status", self.get_status())


def create_app(state_file, event_bus=None):
    app = Flask(__name__, template_folder=str(Path(__file__).parent / "templates"))
    app.config["STATE_FILE"] = Path(state_file)
    app.config["LOG_FILE"] = Path(__file__).parent / "logs" / "runs.jsonl"
    app.config["QUEUE_FILE"] = Path(__file__).parent / "priority_queue.json"

    socketio = SocketIO(app, async_mode="threading", cors_allowed_origins="*")

    # Wire EventBus -> SocketIO bridge
    bus = event_bus or get_bus()

    def bridge(event_type):
        """Forward EventBus events to all WebSocket clients."""
        def handler(data):
            socketio.emit(event_type, data or {})
        return handler

    for evt in [
        "scan_started", "scan_progress", "scan_complete",
        "function_started", "function_mode", "function_complete",
        "tool_call", "tool_result", "model_text",
        "score_update", "state_changed", "run_logged",
        "worker_started", "worker_progress", "worker_stopped",
    ]:
        bus.on(evt, bridge(evt))

    # --- Data loading helpers ---

    def load_state():
        sf = app.config["STATE_FILE"]
        if not sf.exists():
            return {"functions": {}, "sessions": [], "project_folder": "unknown", "last_scan": None}
        # Retry on partial read (race with concurrent save_state)
        for attempt in range(3):
            try:
                with open(sf, "r") as f:
                    return json.load(f)
            except (json.JSONDecodeError, ValueError):
                if attempt < 2:
                    import time
                    time.sleep(0.1)
        return {"functions": {}, "sessions": [], "project_folder": "unknown", "last_scan": None}

    def _save_state_inline(state):
        """Save state from web.py context — uses fun_doc's lock if available."""
        sf = app.config["STATE_FILE"]
        try:
            from fun_doc import _state_lock
            with _state_lock:
                with open(sf, "w") as f:
                    json.dump(state, f, indent=2, default=str)
        except ImportError:
            with open(sf, "w") as f:
                json.dump(state, f, indent=2, default=str)

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

    # --- Compute functions ---

    def compute_deduction_breakdown(funcs):
        cats = defaultdict(lambda: {"count": 0, "total_pts": 0.0, "functions": 0})
        for f in funcs.values():
            seen = set()
            for d in f.get("deductions", []):
                cat = d.get("category", "unknown")
                if not d.get("fixable", False):
                    continue
                cats[cat]["count"] += d.get("count", 1)
                cats[cat]["total_pts"] += d.get("points", 0)
                if cat not in seen:
                    cats[cat]["functions"] += 1
                    seen.add(cat)
        return sorted(
            [{"category": k, **v} for k, v in cats.items()],
            key=lambda x: x["total_pts"], reverse=True,
        )

    def compute_roi_queue(funcs, queue):
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
                "key": key, "name": func["name"], "address": func["address"],
                "program": func.get("program_name", ""), "score": func.get("score", 0),
                "fixable": round(fixable, 1), "callers": callers, "roi": round(roi, 1),
                "is_leaf": func.get("is_leaf", False),
                "last_result": func.get("last_result"),
                "pinned": key in pinned,
                "classification": func.get("classification", ""),
            })
        candidates.sort(key=lambda x: (not x["pinned"], -x["roi"]))
        return candidates

    def compute_run_stats(logs):
        if not logs:
            return {"total_runs": 0, "today_runs": 0, "avg_delta": 0, "success_rate": 0, "by_provider": {}, "stuck_functions": []}
        today = datetime.now().date().isoformat()
        today_logs = [l for l in logs if l.get("timestamp", "").startswith(today)]
        deltas = []
        success = 0
        by_provider = defaultdict(lambda: {"runs": 0, "deltas": []})
        func_results = defaultdict(lambda: {"fails": 0, "name": "", "address": ""})
        for l in logs:
            before, after = l.get("score_before"), l.get("score_after")
            result, provider = l.get("result", ""), l.get("provider", "unknown")
            if before is not None and after is not None:
                deltas.append(after - before)
                by_provider[provider]["deltas"].append(after - before)
            by_provider[provider]["runs"] += 1
            if result == "completed":
                success += 1
            fkey = f"{l.get('program', '')}::{l.get('address', '')}"
            func_results[fkey]["name"] = l.get("function", "")
            func_results[fkey]["address"] = l.get("address", "")
            if result in ("failed", "needs_redo"):
                func_results[fkey]["fails"] += 1
        provider_stats = {}
        for p, data in by_provider.items():
            d = data["deltas"]
            provider_stats[p] = {"runs": data["runs"], "avg_delta": round(sum(d) / len(d), 1) if d else 0}
        stuck = sorted(
            [{"name": v["name"], "address": v["address"], "fails": v["fails"]} for v in func_results.values() if v["fails"] >= 3],
            key=lambda x: x["fails"], reverse=True,
        )[:10]
        return {
            "total_runs": len(logs), "today_runs": len(today_logs),
            "avg_delta": round(sum(deltas) / len(deltas), 1) if deltas else 0,
            "success_rate": round(success / len(logs) * 100, 1) if logs else 0,
            "by_provider": provider_stats, "stuck_functions": stuck,
        }

    def compute_stats(state):
        all_funcs = state.get("functions", {})
        active_binary = state.get("active_binary")
        # Available binaries: merge Ghidra project files + already-scanned
        folder = state.get("project_folder", "/")
        project_binaries = _fetch_project_binaries(folder)
        scanned_binaries = sorted(set(
            f.get("program_name", "unknown") for f in all_funcs.values()
        ))
        available_binaries = sorted(set(project_binaries + scanned_binaries))
        # Filter to active binary if set
        if active_binary:
            funcs = {k: v for k, v in all_funcs.items() if v.get("program_name") == active_binary}
        else:
            funcs = all_funcs
        total = len(funcs)
        queue = load_queue()
        if total == 0:
            return {
                "total": 0, "done": 0, "fixable": 0, "needs_work": 0, "pct": 0,
                "buckets": {}, "by_program": {}, "sessions": [], "roi_queue": [],
                "all_functions": [], "deduction_breakdown": [],
                "run_stats": compute_run_stats([]),
                "project_folder": state.get("project_folder", "unknown"),
                "active_binary": active_binary,
                "available_binaries": available_binaries,
                "available_folders": _fetch_project_folders(),
                "last_scan": state.get("last_scan"),
            }
        done = sum(1 for f in funcs.values() if f["score"] >= 90)
        fixable_count = sum(1 for f in funcs.values() if 70 <= f["score"] < 90)
        needs_work = sum(1 for f in funcs.values() if f["score"] < 70)
        pct = (done / total * 100) if total > 0 else 0
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
        by_program = defaultdict(lambda: {"total": 0, "done": 0, "remaining": 0})
        for f in funcs.values():
            prog = f.get("program_name", "unknown")
            by_program[prog]["total"] += 1
            if f["score"] >= 90: by_program[prog]["done"] += 1
            else: by_program[prog]["remaining"] += 1
        func_list = []
        for key, func in funcs.items():
            if func.get("is_thunk") or func.get("is_external"):
                continue
            func_list.append({
                "key": key, "name": func["name"], "address": func["address"],
                "program": func.get("program_name", ""), "score": func["score"],
                "fixable": round(func.get("fixable", 0), 1),
                "callers": func.get("caller_count", 0),
                "is_leaf": func.get("is_leaf", False),
                "last_result": func.get("last_result"),
            })
        func_list.sort(key=lambda x: x["score"])
        # Limit to 200 for initial page render (prevents 24MB pages with 61K functions)
        func_list = func_list[:200]
        return {
            "total": total, "done": done, "fixable": fixable_count, "needs_work": needs_work,
            "pct": round(pct, 1), "buckets": buckets, "by_program": dict(by_program),
            "sessions": state.get("sessions", [])[-10:],
            "roi_queue": compute_roi_queue(funcs, queue)[:50],
            "all_functions": func_list,
            "deduction_breakdown": compute_deduction_breakdown(funcs),
            "run_stats": compute_run_stats(load_run_logs()),
            "project_folder": state.get("project_folder", "unknown"),
            "active_binary": active_binary,
            "available_binaries": available_binaries,
            "available_folders": _fetch_project_folders(),
            "last_scan": state.get("last_scan"),
        }

    # --- SocketIO event handlers ---

    @socketio.on("connect")
    def handle_connect():
        state = load_state()
        stats = compute_stats(state)
        sio_emit("initial_state", stats)

    _scan_thread = None

    @socketio.on("request_rescan")
    def handle_rescan(data):
        nonlocal _scan_thread
        if _scan_thread and _scan_thread.is_alive():
            sio_emit("scan_error", {"error": "Scan already in progress"})
            return
        refresh = data.get("refresh", False) if data else False
        program_filter = data.get("program") if data else None

        def run_scan():
            try:
                # Delayed import to avoid circular dependency
                from fun_doc import scan_functions, load_state, save_state
                state = load_state()
                folder = state.get("project_folder", "/Mods/PD2-S12")
                scan_functions(state, folder, refresh=refresh, binary_filter=program_filter)
            except Exception as e:
                bus.emit("scan_error", {"error": str(e)})

        _scan_thread = threading.Thread(target=run_scan, daemon=True)
        _scan_thread.start()
        sio_emit("scan_acknowledged", {"refresh": refresh, "program": program_filter})

    # --- Worker management ---
    worker_mgr = WorkerManager(app.config["STATE_FILE"], bus, socketio)

    @socketio.on("request_start_worker")
    def handle_start_worker(data):
        try:
            provider = (data or {}).get("provider", "claude")
            continuous = bool((data or {}).get("continuous", False))
            count = max(1, min(500, int((data or {}).get("count", 5))))
            model = (data or {}).get("model") or None
            binary = (data or {}).get("binary") or None
            worker_id = worker_mgr.start_worker(
                provider=provider, count=count, model=model, binary=binary, continuous=continuous,
            )
            sio_emit("worker_started_ack", {"worker_id": worker_id})
        except ValueError as e:
            sio_emit("worker_error", {"error": str(e)})

    @socketio.on("request_stop_worker")
    def handle_stop_worker(data):
        try:
            worker_id = (data or {}).get("worker_id")
            if not worker_id:
                sio_emit("worker_error", {"error": "worker_id required"})
                return
            worker_mgr.stop_worker(worker_id)
            sio_emit("worker_stop_ack", {"worker_id": worker_id})
        except ValueError as e:
            sio_emit("worker_error", {"error": str(e)})

    @socketio.on("request_worker_status")
    def handle_worker_status(data=None):
        sio_emit("worker_status", worker_mgr.get_status())

    # --- HTTP routes ---

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
        socketio.emit("queue_changed", {"action": "pin", "key": key})
        return jsonify({"ok": True})

    @app.route("/api/queue/unpin", methods=["POST"])
    def unpin_function():
        data = request.json
        key = data.get("key")
        if not key:
            return jsonify({"error": "key required"}), 400
        queue = load_queue()
        queue["pinned"] = [k for k in queue["pinned"] if k != key]
        save_queue(queue)
        socketio.emit("queue_changed", {"action": "unpin", "key": key})
        return jsonify({"ok": True})

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
        socketio.emit("queue_changed", {"action": "skip", "key": key})
        return jsonify({"ok": True})

    @app.route("/api/queue/unskip", methods=["POST"])
    def unskip_function():
        data = request.json
        key = data.get("key")
        if not key:
            return jsonify({"error": "key required"}), 400
        queue = load_queue()
        queue["skipped"] = [k for k in queue["skipped"] if k != key]
        save_queue(queue)
        socketio.emit("queue_changed", {"action": "unskip", "key": key})
        return jsonify({"ok": True})

    # --- Folder / binary selection ---

    def _fetch_project_binaries(folder):
        """Fetch all binaries from Ghidra project via HTTP endpoint."""
        import requests
        try:
            r = requests.get(
                "http://127.0.0.1:8089/list_project_files",
                params={"folder": folder},
                timeout=5,
            )
            r.raise_for_status()
            data = r.json()
            files = data.get("files", [])
            return sorted(
                f["name"] for f in files
                if isinstance(f, dict) and f.get("content_type") == "Program"
            )
        except Exception:
            return []

    @app.route("/api/context", methods=["GET"])
    def get_context():
        state = load_state()
        folder = state.get("project_folder", "/")
        # Merge: project files from Ghidra + any binaries already scanned
        project_binaries = _fetch_project_binaries(folder)
        scanned_binaries = sorted(set(
            f.get("program_name", "unknown")
            for f in state.get("functions", {}).values()
        ))
        all_binaries = sorted(set(project_binaries + scanned_binaries))
        return jsonify({
            "project_folder": folder,
            "active_binary": state.get("active_binary"),
            "available_binaries": all_binaries,
        })

    @app.route("/api/context/binary", methods=["POST"])
    def set_active_binary():
        data = request.json
        binary = data.get("binary")  # None or "" to clear filter
        state = load_state()
        if binary:
            state["active_binary"] = binary
        else:
            state.pop("active_binary", None)
        _save_state_inline(state)
        socketio.emit("state_changed")
        return jsonify({"ok": True, "active_binary": state.get("active_binary")})

    @app.route("/api/context/folder", methods=["POST"])
    def set_project_folder():
        data = request.json
        folder = data.get("folder")
        if not folder:
            return jsonify({"error": "folder required"}), 400
        state = load_state()
        state["project_folder"] = folder
        _save_state_inline(state)
        socketio.emit("state_changed")
        return jsonify({"ok": True, "project_folder": folder})

    def _fetch_project_folders():
        """Recursively discover all folders with binaries in the Ghidra project."""
        import requests
        folders = []
        def _walk(path):
            try:
                r = requests.get("http://127.0.0.1:8089/list_project_files", params={"folder": path}, timeout=5)
                r.raise_for_status()
                data = r.json()
                subfolders = data.get("folders", [])
                files = data.get("files", [])
                has_programs = any(f.get("content_type") == "Program" for f in files if isinstance(f, dict))
                if has_programs:
                    folders.append(path)
                for sf in subfolders:
                    _walk(f"{path}/{sf}" if path != "/" else f"/{sf}")
            except Exception:
                pass
        _walk("/")
        return sorted(folders)

    @app.route("/api/context/folders", methods=["GET"])
    def get_available_folders():
        return jsonify({"folders": _fetch_project_folders()})

    @app.route("/api/cross_binary_progress", methods=["GET"])
    def cross_binary_progress():
        """Cross-binary progress summary — all binaries in the current folder."""
        state = load_state()
        all_funcs = state.get("functions", {})
        by_binary = defaultdict(lambda: {"total": 0, "done": 0, "fixable": 0, "needs_work": 0, "avg_score": 0, "total_fixable_pts": 0})
        for f in all_funcs.values():
            prog = f.get("program_name", "unknown")
            score = f.get("score", 0)
            by_binary[prog]["total"] += 1
            if score >= 90:
                by_binary[prog]["done"] += 1
            elif score >= 70:
                by_binary[prog]["fixable"] += 1
            else:
                by_binary[prog]["needs_work"] += 1
            by_binary[prog]["avg_score"] += score
            by_binary[prog]["total_fixable_pts"] += f.get("fixable", 0)
        result = []
        for prog, info in sorted(by_binary.items()):
            info["avg_score"] = round(info["avg_score"] / info["total"], 1) if info["total"] > 0 else 0
            info["total_fixable_pts"] = round(info["total_fixable_pts"], 0)
            info["pct_done"] = round(info["done"] / info["total"] * 100, 1) if info["total"] > 0 else 0
            info["name"] = prog
            result.append(info)
        return jsonify({"binaries": result})

    return app, socketio
