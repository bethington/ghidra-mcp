"""conformance_api.py -- Flask blueprint exposing the Ghidra-native conformance read layer
(conformance_dashboard.py) as JSON, for the confidence dashboard. LIVE reads from Ghidra
per the chosen read model -- no cache.

Wire into web.py's create_app with two lines (kept out of web.py here to avoid touching
its in-flight WIP):

    from conformance_api import conf_bp
    app.register_blueprint(conf_bp)

and, to push a live refresh when a lane changes Ghidra state, emit from the worker
completion path:

    socketio.emit("conf_changed", {})

Routes:
    GET /api/conformance/summary             -> rollup option (headline + marginals)
    GET /api/conformance/matrix              -> DOC_ x CONF_ joint
    GET /api/conformance/intake              -> untriaged / in-scope / excluded counts
    GET /api/conformance/inventory?q=&limit= -> searchable in-scope function list
    GET /api/conformance/function/<addr>     -> one function's drawer data
"""
from flask import Blueprint, jsonify, request

import conformance_dashboard as cd

conf_bp = Blueprint("conformance", __name__)


@conf_bp.route("/api/conformance/summary")
def _summary():
    return jsonify(cd.summary())


@conf_bp.route("/api/conformance/matrix")
def _matrix():
    return jsonify(cd.matrix())


@conf_bp.route("/api/conformance/intake")
def _intake():
    return jsonify(cd.intake())


@conf_bp.route("/api/conformance/inventory")
def _inventory():
    try:
        limit = max(1, min(500, int(request.args.get("limit", 100))))
    except (TypeError, ValueError):
        limit = 100
    return jsonify(cd.inventory(search=request.args.get("q", ""), limit=limit))


@conf_bp.route("/api/conformance/function/<addr>")
def _function(addr):
    return jsonify(cd.function_detail(addr))
