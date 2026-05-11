"""SQLAlchemy event hook that logs slow queries.

Threshold defaults to 100 ms; tunable via the constructor of the storage
factory. Logger name is ``fun_doc.storage.slow_query`` so users can route it
to a separate file or silence it via the standard logging config.

Why we have this: the storage layer is brand new and the workload mix
(dashboard reads + worker INSERTs + audit pass UPDATEs) hasn't been profiled
in production. A passive slow-log gives us a free signal for index
regressions and N+1 patterns without paying for a metrics pipeline.
"""

from __future__ import annotations

import logging
import time

logger = logging.getLogger("fun_doc.storage.slow_query")


def attach(engine, threshold_ms: int = 100) -> None:
    """Wire before/after-cursor-execute hooks onto ``engine``.

    Idempotent: calling twice will register two listeners, so callers should
    only call this once per engine (the storage factory does so).
    """
    from sqlalchemy import event

    @event.listens_for(engine, "before_cursor_execute")
    def _before(conn, cursor, statement, parameters, context, executemany):
        context._fun_doc_t0 = time.perf_counter()

    @event.listens_for(engine, "after_cursor_execute")
    def _after(conn, cursor, statement, parameters, context, executemany):
        t0 = getattr(context, "_fun_doc_t0", None)
        if t0 is None:
            return
        elapsed_ms = (time.perf_counter() - t0) * 1000
        if elapsed_ms < threshold_ms:
            return
        logger.warning(
            "slow_query elapsed_ms=%.1f executemany=%s sql=%s",
            elapsed_ms,
            executemany,
            _truncate(statement),
        )


def _truncate(sql: str, limit: int = 500) -> str:
    sql = " ".join(sql.split())
    if len(sql) <= limit:
        return sql
    return sql[: limit - 3] + "..."
