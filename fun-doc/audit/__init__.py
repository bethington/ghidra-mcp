"""
fun-doc audit loop — Phase 1 walking skeleton.

This subpackage hosts the detection infrastructure for the self-improving
audit loop described in the design. Phase 1 is report-only: rules are
evaluated, signatures are tracked, triggers are queued — but no agent
runs, nothing is committed, nothing lands in main.

Phase 1 modules:
    registry    — persistent signature state machine (cooldown, circuit breaker)
    watcher     — event-bus tap + periodic rule evaluator
    rules.yaml  — five seed rules, all mode: report

Later phases will add: agent.py (the fix-writing worker), ladder.py
(promotion state machine), sweep.py (LLM periodic sweep).
"""
