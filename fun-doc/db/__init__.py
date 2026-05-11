"""Database migration runner and schema files for fun-doc storage layer.

The migration files live in ``fun-doc/db/migrations/`` as raw SQL — one file
per schema version, per backend dialect (``NNNN_name.sql`` for Postgres,
``NNNN_name.sqlite.sql`` for SQLite). Raw SQL keeps the bootstrap step
transparent and avoids ORM-driven migration tools that break in opaque ways
when the schema is edited by hand.

Use ``python -m fun_doc.db.migrate --backend sqlite`` to bring a fresh
database up to the latest schema.
"""
