"""Apply knowledge_schema.sql to the PostgreSQL database."""
import os
import psycopg2
import re
import sys

DB_CONFIG = {
    "host": os.getenv("KNOWLEDGE_DB_HOST", "10.0.10.30"),
    "port": int(os.getenv("KNOWLEDGE_DB_PORT", "5432")),
    "dbname": os.getenv("KNOWLEDGE_DB_NAME", "bsim"),
    "user": os.getenv("KNOWLEDGE_DB_USER", "ben"),
    "password": os.getenv("KNOWLEDGE_DB_PASSWORD", os.getenv("BSIM_DB_PASSWORD", "")),
    "connect_timeout": 5,
}


def apply_schema():
    conn = psycopg2.connect(**DB_CONFIG)
    conn.autocommit = True
    cur = conn.cursor()

    with open("scripts/knowledge_schema.sql", "r") as f:
        sql = f.read()

    # Remove psql meta-commands
    lines = sql.split("\n")
    clean_lines = [l for l in lines if not l.strip().startswith("\\")]
    clean_sql = "\n".join(clean_lines)

    # Split into statements respecting $$ blocks
    statements = []
    current = []
    in_dollar = False
    for line in clean_lines:
        current.append(line)
        dollar_count = line.count("$$")
        if dollar_count % 2 == 1:
            in_dollar = not in_dollar
        if not in_dollar and line.rstrip().endswith(";"):
            stmt = "\n".join(current).strip()
            if stmt and stmt != ";":
                statements.append(stmt)
            current = []

    if current:
        stmt = "\n".join(current).strip()
        if stmt:
            statements.append(stmt)

    success_count = 0
    skip_count = 0
    error_count = 0

    for i, stmt in enumerate(statements):
        if not stmt.strip() or stmt.strip() == ";":
            continue
        try:
            cur.execute(stmt)
            success_count += 1
            print(f"  [{i+1}] OK")
        except Exception as e:
            err = str(e).strip()
            if "already exists" in err or "duplicate" in err.lower():
                skip_count += 1
                print(f"  [{i+1}] Already exists (OK)")
                conn.rollback()
                conn.autocommit = True
            elif "null value in column" in err and "url" in err:
                skip_count += 1
                print(f"  [{i+1}] Skipped knowledge_sources insert (url constraint)")
                conn.rollback()
                conn.autocommit = True
            else:
                error_count += 1
                print(f"  [{i+1}] ERROR: {err}")
                conn.rollback()
                conn.autocommit = True

    # Verify tables
    cur.execute("""
        SELECT tablename FROM pg_tables
        WHERE schemaname = 'public'
        AND tablename IN ('ordinal_mappings', 'documented_functions', 'propagation_log')
        ORDER BY tablename
    """)
    tables = [t[0] for t in cur.fetchall()]

    print(f"\nResults: {success_count} OK, {skip_count} skipped, {error_count} errors")
    print(f"Tables verified: {tables}")

    cur.close()
    conn.close()
    return error_count == 0 and len(tables) == 3


if __name__ == "__main__":
    ok = apply_schema()
    sys.exit(0 if ok else 1)
