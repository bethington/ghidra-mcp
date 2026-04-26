"""Storage abstraction for fun-doc.

Replaces the file-locked ``state.json`` persistence layer with a SQL backend
that has two engines:

  * ``sqlite``    — stdlib, zero install. Default for users who haven't
                    opted into Postgres. File at ``fun-doc/state.db``.
  * ``postgres``  — primary path for the maintainer. Same Postgres instance
                    that hosts ``re_kb`` and (eventually) ``bsim``. Schema
                    is ``fun_doc.*``.

Selection is driven by ``priority_queue.json -> config.storage.backend``
plus the ``FUN_DOC_DB_URL`` env var, which always wins when set:

    {
      "config": {
        "storage": {
          "backend": "postgres",
          "url": "postgresql://re_kb:***@10.0.10.30:5432/bsim",
          "schema": "fun_doc"
        }
      }
    }

The schema layer (``models.py``) defines SQLAlchemy Core ``Table`` objects
that are dialect-neutral. The query layer (``repository.py``) speaks SQL
through the engine and returns plain dicts — the rest of fun-doc never
touches an ORM session, which keeps the migration mechanical.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional


DEFAULT_SQLITE_PATH = Path(__file__).parent.parent / "state.db"
SLOW_QUERY_THRESHOLD_MS = 100  # logger fires above this (see slow_query_log.py)


@dataclass(frozen=True)
class StorageConfig:
    """Resolved configuration for the storage layer.

    Always pass through ``resolve_config`` so env var precedence and SQLite
    path defaults are applied consistently across CLI scripts, the worker,
    and the dashboard.
    """

    backend: str  # "sqlite" | "postgres"
    url: str  # SQLAlchemy-compatible URL
    schema: Optional[str] = None  # Postgres only; None for SQLite

    @property
    def is_postgres(self) -> bool:
        return self.backend == "postgres"

    @property
    def is_sqlite(self) -> bool:
        return self.backend == "sqlite"


def resolve_config(config_block: Optional[dict] = None) -> StorageConfig:
    """Merge env vars, the config block, and defaults into a StorageConfig.

    Precedence (highest first):
      1. ``FUN_DOC_DB_URL`` env var (forces postgres if set, unless it starts
         with ``sqlite:``)
      2. ``config_block.backend`` + ``config_block.url``
      3. Default: sqlite at ``fun-doc/state.db``
    """
    cfg = config_block or {}
    env_url = os.environ.get("FUN_DOC_DB_URL")
    if env_url:
        if env_url.startswith("sqlite:"):
            return StorageConfig(backend="sqlite", url=env_url, schema=None)
        return StorageConfig(
            backend="postgres",
            url=env_url,
            schema=cfg.get("schema") or "fun_doc",
        )

    backend = (cfg.get("backend") or "sqlite").lower()
    if backend == "postgres":
        url = cfg.get("url")
        if not url:
            raise ValueError(
                "storage.backend is 'postgres' but no url provided. Set "
                "FUN_DOC_DB_URL env var or storage.url in priority_queue.json."
            )
        return StorageConfig(
            backend="postgres",
            url=url,
            schema=cfg.get("schema") or "fun_doc",
        )

    if backend == "sqlite":
        url = cfg.get("url") or f"sqlite:///{DEFAULT_SQLITE_PATH}"
        if not url.startswith("sqlite:"):
            # Treat bare paths as sqlite paths.
            url = f"sqlite:///{url}"
        return StorageConfig(backend="sqlite", url=url, schema=None)

    raise ValueError(
        f"Unknown storage backend: {backend!r} (expected 'sqlite' or 'postgres')"
    )


def make_engine(config: StorageConfig):
    """Build a SQLAlchemy Engine from a StorageConfig.

    Imports SQLAlchemy lazily so the rest of fun-doc loads cleanly on a
    machine without the storage deps installed (the worker imports a lot at
    module load time and we don't want to break that path for users still on
    state.json during the cutover window).
    """
    from sqlalchemy import create_engine, event

    if config.is_sqlite:
        # ``check_same_thread=False`` matches our worker model (single writer
        # but background dashboard reads are fine because we serialize through
        # a transaction). WAL is set in the schema bootstrap PRAGMA.
        engine = create_engine(
            config.url,
            connect_args={"check_same_thread": False},
            future=True,
        )
    else:
        engine = create_engine(config.url, future=True, pool_pre_ping=True)

    # Wire the slow-query logger.
    from .slow_query_log import attach as attach_slow_query_log

    attach_slow_query_log(engine, threshold_ms=SLOW_QUERY_THRESHOLD_MS)
    return engine


def make_repository(config: Optional[StorageConfig] = None):
    """Convenience: resolve config, build engine, return a Repository.

    For most callers this is the only entry point they need:

        from fun_doc.storage import make_repository
        repo = make_repository()
        repo.upsert_function(...)
    """
    if config is None:
        config = resolve_config()
    engine = make_engine(config)
    from .repository import Repository

    return Repository(engine, config)


__all__ = [
    "StorageConfig",
    "resolve_config",
    "make_engine",
    "make_repository",
    "DEFAULT_SQLITE_PATH",
    "SLOW_QUERY_THRESHOLD_MS",
]
