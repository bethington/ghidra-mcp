"""falsify_api.py -- Flask blueprint exposing the falsifiability verdict map
as JSON for the pipeline dashboard.

Reads the SQL store (functions_workflow's migration-0007 columns), NOT Ghidra:
the sweep and the worker stage keep SQL complete (passed + contradicted),
while Ghidra carries only the refutations — so SQL is the layer that can
answer "how much of this binary has actually been checked".

Wire into web.py's create_app (same two-line pattern as conformance_api):

    from falsify_api import falsify_bp
    app.register_blueprint(falsify_bp)

Routes:
    GET /api/falsify/summary                       -> per-binary status counts
    GET /api/falsify/findings?program=&status=&limit= -> function-level detail
"""
from flask import Blueprint, jsonify, request

falsify_bp = Blueprint("falsify", __name__)

_repo = None


def _get_repo():
    """Lazy, cached repository. Broken storage degrades the routes to an
    error payload rather than a 500 (dashboard convention)."""
    global _repo
    if _repo is None:
        from storage import make_engine, resolve_config
        from storage.repository import Repository

        cfg = resolve_config()
        _repo = Repository(make_engine(cfg), cfg)
    return _repo


@falsify_bp.route("/api/falsify/summary")
def falsify_summary():
    try:
        from sqlalchemy import func, select

        repo = _get_repo()
        t = repo.t_workflow
        with repo._engine.connect() as conn:
            rows = conn.execute(
                select(t.c.program_path, t.c.falsify_status, func.count())
                .group_by(t.c.program_path, t.c.falsify_status)
            ).all()
        per_binary = {}
        totals = {"unchecked": 0, "passed": 0, "contradicted": 0,
                  "unfalsifiable": 0}
        for program_path, status, n in rows:
            b = per_binary.setdefault(program_path, {
                "unchecked": 0, "passed": 0, "contradicted": 0,
                "unfalsifiable": 0})
            key = status or "unchecked"
            b[key] = b.get(key, 0) + n
            totals[key] = totals.get(key, 0) + n
        return jsonify({"totals": totals, "per_binary": per_binary})
    except Exception as exc:  # noqa: BLE001 - report, don't 500 the dashboard
        print(f"[falsify_api] summary failed: {exc}")
        return jsonify({"error": "falsify summary unavailable",
                        "detail": str(exc)})


@falsify_bp.route("/api/falsify/findings")
def falsify_findings():
    program = request.args.get("program") or None
    status = request.args.get("status") or "contradicted"
    try:
        limit = min(int(request.args.get("limit", 100)), 1000)
    except ValueError:
        limit = 100
    try:
        from sqlalchemy import select

        repo = _get_repo()
        t = repo.t_workflow
        q = (select(t.c.program_path, t.c.address, t.c.name, t.c.score,
                    t.c.falsify_status, t.c.falsify_checked_at,
                    t.c.falsify_findings, t.c.falsify_source)
             .where(t.c.falsify_status == status)
             .limit(limit))
        if program:
            q = q.where(t.c.program_path == program)
        with repo._engine.connect() as conn:
            rows = conn.execute(q).mappings().all()
        out = []
        for r in rows:
            checked = r["falsify_checked_at"]
            out.append({
                "program": r["program_path"],
                "address": r["address"],
                "name": r["name"],
                "score": r["score"],
                "status": r["falsify_status"],
                "source": r["falsify_source"],
                "checked_at": checked.isoformat()
                if hasattr(checked, "isoformat") else checked,
                "findings": r["falsify_findings"] or [],
            })
        return jsonify({"status": status, "count": len(out), "functions": out})
    except Exception as exc:  # noqa: BLE001
        print(f"[falsify_api] findings failed: {exc}")
        return jsonify({"error": "falsify findings unavailable",
                        "detail": str(exc)})
