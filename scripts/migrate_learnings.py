#!/usr/bin/env python
"""
Migrate RE loop learnings from flat files into the knowledge DB.

Reads:
  - workflows/learnings.md     -> ordinal_mappings, community_insights (structure layouts)
  - workflows/loop_state.json  -> documented_functions
  - workflows/community_names.json -> ordinal_mappings (community source)

DB config via env vars:
  KNOWLEDGE_DB_HOST     (default: 10.0.10.30)
  KNOWLEDGE_DB_PORT     (default: 5432)
  KNOWLEDGE_DB_NAME     (default: bsim)
  KNOWLEDGE_DB_USER     (default: ben)
  KNOWLEDGE_DB_PASSWORD (or BSIM_DB_PASSWORD)

Usage:
  python scripts/migrate_learnings.py             # run migration
  python scripts/migrate_learnings.py --dry-run   # preview without writing
"""

import argparse
import json
import os
import re
import sys
from pathlib import Path

try:
    import psycopg2
    import psycopg2.extras
except ImportError:
    psycopg2 = None


# ---------------------------------------------------------------------------
# Paths (relative to project root)
# ---------------------------------------------------------------------------

SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent
LEARNINGS_PATH = PROJECT_ROOT / "workflows" / "learnings.md"
LOOP_STATE_PATH = PROJECT_ROOT / "workflows" / "loop_state.json"
COMMUNITY_NAMES_PATH = PROJECT_ROOT / "workflows" / "community_names.json"


# ---------------------------------------------------------------------------
# DB connection
# ---------------------------------------------------------------------------

def get_db_config():
    password = os.environ.get("KNOWLEDGE_DB_PASSWORD") or os.environ.get("BSIM_DB_PASSWORD")
    if not password:
        print("WARNING: No DB password found in KNOWLEDGE_DB_PASSWORD or BSIM_DB_PASSWORD env vars.")
        print("         Set one of these before running without --dry-run.")
    return {
        "host": os.environ.get("KNOWLEDGE_DB_HOST", "10.0.10.30"),
        "port": int(os.environ.get("KNOWLEDGE_DB_PORT", "5432")),
        "dbname": os.environ.get("KNOWLEDGE_DB_NAME", "bsim"),
        "user": os.environ.get("KNOWLEDGE_DB_USER", "ben"),
        "password": password or "",
    }


def connect_db():
    if psycopg2 is None:
        print("ERROR: psycopg2 is not installed. Run: pip install psycopg2-binary")
        sys.exit(1)
    cfg = get_db_config()
    return psycopg2.connect(**cfg)


# ---------------------------------------------------------------------------
# Parse binary path -> (binary_name, version)
# ---------------------------------------------------------------------------

def parse_binary_path(path):
    """
    Convert a project path like '/Vanilla/1.13d/D2Common.dll' to
    ('D2Common.dll', '1.13d').
    """
    parts = Path(path).parts
    # Last component is the binary name
    binary_name = parts[-1] if parts else path
    # Second-to-last is typically the version
    version = parts[-2] if len(parts) >= 2 else "unknown"
    return binary_name, version


def parse_binary_tag(tag):
    """
    Parse '[D2Common.dll@1.13d]' or '[D2Common.dll]' tags from learnings.md.
    Returns (binary_name, version) or (binary_name, None).
    """
    m = re.match(r"\[([^@\]]+)(?:@([^\]]+))?\]", tag)
    if m:
        return m.group(1).strip(), m.group(2).strip() if m.group(2) else None
    return None, None


# ---------------------------------------------------------------------------
# 1. Parse learnings.md -> ordinal mappings
# ---------------------------------------------------------------------------

def extract_ordinal_mappings_from_learnings(text):
    """
    Extract ordinal mappings from learnings.md.
    Handles multiple line formats:
      - "Ordinal 10375: GetUnitPosition -- ..."
      - "10600: GetItemDataRecord (D2GetItemsBIN, ...)"
      - Inline mentions like "10505: TraceLineForCollision"
    Returns list of dicts.
    """
    mappings = []

    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("- "):
            continue

        # Determine binary context from line tag
        binary_name = "D2Common.dll"
        version = "1.00"  # default for untagged entries

        # Check for [Binary@Version] tag
        tag_match = re.search(r"\[([^\]]+)\]", line)
        if tag_match:
            bn, ver = parse_binary_tag(tag_match.group(0))
            if bn:
                binary_name = bn
            if ver:
                version = ver

        # Determine calling convention if mentioned
        calling_convention = None
        if "__fastcall" in line:
            calling_convention = "__fastcall"
        elif "__thiscall" in line:
            calling_convention = "__thiscall"
        elif "__cdecl" in line:
            calling_convention = "__cdecl"
        elif "__stdcall" in line:
            calling_convention = "__stdcall"

        # Pattern 1: "Ordinal NNNNN: FunctionName"
        # e.g., "- Ordinal 10375: GetUnitPosition -- ..."
        for m in re.finditer(r"Ordinal\s+(\d+):\s+(\w+)", line):
            ordinal = int(m.group(1))
            func_name = m.group(2)
            # Extract notes: everything after the function name up to next ordinal
            notes_start = m.end()
            notes_text = line[notes_start:].strip().lstrip("--").lstrip(" ").lstrip("\u2014").strip()
            # Trim notes at a reasonable length
            if len(notes_text) > 500:
                notes_text = notes_text[:497] + "..."
            mappings.append({
                "ordinal": ordinal,
                "binary_name": binary_name,
                "version": version,
                "function_name": func_name,
                "calling_convention": calling_convention,
                "source": "re_loop_learnings",
                "confidence": 0.95,
                "notes": notes_text if notes_text else None,
            })

        # Pattern 2: "NNNNN: FunctionName" (inline compact format)
        # e.g., "10600: GetItemDataRecord (D2GetItemsBIN, stride 0x1a8)"
        # But skip if already captured by Ordinal pattern above
        captured_ordinals = {m["ordinal"] for m in mappings
                            if m["binary_name"] == binary_name and m["version"] == version}
        for m in re.finditer(r"(?<!\w)(\d{5}):\s+([A-Z]\w+)", line):
            ordinal = int(m.group(1))
            if ordinal in captured_ordinals:
                continue
            func_name = m.group(2)
            # Gather context around the match as notes
            context_start = max(0, m.start() - 50)
            context_end = min(len(line), m.end() + 100)
            notes_text = line[m.end():context_end].strip().lstrip(",").strip()
            if len(notes_text) > 500:
                notes_text = notes_text[:497] + "..."
            mappings.append({
                "ordinal": ordinal,
                "binary_name": binary_name,
                "version": version,
                "function_name": func_name,
                "calling_convention": calling_convention,
                "source": "re_loop_learnings",
                "confidence": 0.90,
                "notes": notes_text if notes_text else None,
            })
            captured_ordinals.add(ordinal)

    return mappings


# ---------------------------------------------------------------------------
# 2. Parse learnings.md -> structure layouts as community_insights
# ---------------------------------------------------------------------------

def extract_structure_layouts(text):
    """
    Extract structure layout sections from learnings.md.
    Each ### heading under ## Structure Layouts becomes one insight.
    Returns list of dicts with keys: title, content.
    """
    layouts = []
    in_structures = False
    current_title = None
    current_lines = []

    for line in text.splitlines():
        # Detect start of Structure Layouts section
        if line.strip() == "## Structure Layouts":
            in_structures = True
            continue

        # End of Structure Layouts on next ## heading
        if in_structures and line.startswith("## ") and not line.startswith("### "):
            # Save last layout
            if current_title and current_lines:
                layouts.append({
                    "title": current_title,
                    "content": "\n".join(current_lines).strip(),
                })
            break

        if not in_structures:
            continue

        # New sub-heading
        if line.startswith("### "):
            if current_title and current_lines:
                layouts.append({
                    "title": current_title,
                    "content": "\n".join(current_lines).strip(),
                })
            current_title = line.lstrip("#").strip()
            current_lines = []
        else:
            current_lines.append(line)

    # Handle case where structure section is at end of file
    if in_structures and current_title and current_lines:
        layouts.append({
            "title": current_title,
            "content": "\n".join(current_lines).strip(),
        })

    return layouts


# ---------------------------------------------------------------------------
# 3. Parse learnings.md -> function family patterns
# ---------------------------------------------------------------------------

def extract_function_families(text):
    """
    Extract function family descriptions from ## Function Families section.
    Returns list of dicts with keys: family_name, description, ordinals.
    """
    families = []
    in_families = False

    for line in text.splitlines():
        if line.strip() == "## Function Families":
            in_families = True
            continue
        if in_families and line.startswith("## "):
            break
        if not in_families:
            continue

        line = line.strip()
        if not line.startswith("- "):
            continue

        # Parse bold family name: "**Family Name**: description"
        m = re.match(r"-\s+(?:\[.*?\]\s+)?\*\*(.+?)\*\*:\s*(.*)", line)
        if m:
            family_name = m.group(1).strip()
            description = m.group(2).strip()
            # Extract ordinals mentioned in the line
            ordinals = [int(x) for x in re.findall(r"\((\d{5})", line)]
            families.append({
                "family_name": family_name,
                "description": description,
                "ordinals": ordinals,
            })

    return families


# ---------------------------------------------------------------------------
# 4. Parse loop_state.json -> documented_functions
# ---------------------------------------------------------------------------

def extract_documented_functions(loop_state):
    """
    Extract all completed entries from loop_state.json across all binaries.
    Returns list of dicts matching documented_functions schema.
    """
    functions = []
    binaries = loop_state.get("binaries", {})

    for binary_path, binary_data in binaries.items():
        binary_name, version = parse_binary_path(binary_path)
        completed = binary_data.get("completed", [])

        for entry in completed:
            status = entry.get("status", "complete")
            # Only include completed/documented entries
            if status not in ("complete", "documented"):
                continue

            deductions = entry.get("deductions", [])
            # Ensure deductions is serializable as JSON
            if isinstance(deductions, list):
                deductions_json = json.dumps(deductions)
            else:
                deductions_json = json.dumps([])

            functions.append({
                "address": entry.get("address", ""),
                "binary_name": binary_name,
                "version": version,
                "old_name": entry.get("old_name"),
                "new_name": entry.get("new_name", ""),
                "score": entry.get("score"),
                "status": status,
                "classification": entry.get("classification"),
                "iteration": entry.get("iteration"),
                "strategy": entry.get("strategy"),
                "plate_comment": None,  # not stored in loop_state
                "prototype": None,      # not stored in loop_state
                "deductions": deductions_json,
                "game_system": None,    # not stored in loop_state
            })

    return functions


# ---------------------------------------------------------------------------
# 5. Parse community_names.json -> ordinal_mappings
# ---------------------------------------------------------------------------

def extract_community_ordinal_mappings(community_data):
    """
    Extract all ordinal->name mappings from community_names.json.
    Returns list of dicts for ordinal_mappings table.
    """
    mappings = []
    dlls = community_data.get("dlls", {})

    for dll_name, versions in dlls.items():
        for version, ordinals in versions.items():
            for ordinal_str, entry in ordinals.items():
                try:
                    ordinal = int(ordinal_str)
                except ValueError:
                    continue

                name = entry.get("name", "")
                source_info = entry.get("source", "community")

                mappings.append({
                    "ordinal": ordinal,
                    "binary_name": dll_name,
                    "version": version,
                    "function_name": name,
                    "calling_convention": None,
                    "source": "community",
                    "confidence": 0.80,
                    "notes": f"Source: {source_info}" if source_info else None,
                })

    return mappings


# ---------------------------------------------------------------------------
# DB upsert helpers
# ---------------------------------------------------------------------------

def upsert_ordinal_mappings(cursor, mappings, dry_run=False):
    """
    Insert/update ordinal mappings. ON CONFLICT -> update name, source, etc.
    Re_loop_learnings source takes precedence over community source.
    """
    sql = """
        INSERT INTO ordinal_mappings
            (ordinal, binary_name, version, function_name, calling_convention,
             source, confidence, notes)
        VALUES
            (%(ordinal)s, %(binary_name)s, %(version)s, %(function_name)s,
             %(calling_convention)s, %(source)s, %(confidence)s, %(notes)s)
        ON CONFLICT (ordinal, binary_name, version) DO UPDATE SET
            function_name = CASE
                WHEN ordinal_mappings.source = 're_loop_learnings'
                     AND EXCLUDED.source = 'community'
                THEN ordinal_mappings.function_name
                ELSE EXCLUDED.function_name
            END,
            calling_convention = COALESCE(EXCLUDED.calling_convention,
                                          ordinal_mappings.calling_convention),
            source = CASE
                WHEN ordinal_mappings.source = 're_loop_learnings'
                     AND EXCLUDED.source = 'community'
                THEN ordinal_mappings.source
                ELSE EXCLUDED.source
            END,
            confidence = GREATEST(EXCLUDED.confidence, ordinal_mappings.confidence),
            notes = CASE
                WHEN EXCLUDED.notes IS NOT NULL AND EXCLUDED.notes != ''
                THEN EXCLUDED.notes
                ELSE ordinal_mappings.notes
            END,
            updated_at = NOW()
    """
    if dry_run:
        return

    psycopg2.extras.execute_batch(cursor, sql, mappings, page_size=200)


def upsert_documented_functions(cursor, functions, dry_run=False):
    """
    Insert/update documented functions. ON CONFLICT -> update fields.
    """
    sql = """
        INSERT INTO documented_functions
            (address, binary_name, version, old_name, new_name, score,
             status, classification, iteration, strategy, plate_comment,
             prototype, deductions, game_system)
        VALUES
            (%(address)s, %(binary_name)s, %(version)s, %(old_name)s,
             %(new_name)s, %(score)s, %(status)s, %(classification)s,
             %(iteration)s, %(strategy)s, %(plate_comment)s, %(prototype)s,
             %(deductions)s::jsonb, %(game_system)s)
        ON CONFLICT (address, binary_name, version) DO UPDATE SET
            old_name = COALESCE(EXCLUDED.old_name, documented_functions.old_name),
            new_name = EXCLUDED.new_name,
            score = EXCLUDED.score,
            status = EXCLUDED.status,
            classification = EXCLUDED.classification,
            iteration = EXCLUDED.iteration,
            strategy = EXCLUDED.strategy,
            plate_comment = COALESCE(EXCLUDED.plate_comment,
                                     documented_functions.plate_comment),
            prototype = COALESCE(EXCLUDED.prototype,
                                 documented_functions.prototype),
            deductions = EXCLUDED.deductions::jsonb,
            game_system = COALESCE(EXCLUDED.game_system,
                                   documented_functions.game_system),
            updated_at = NOW()
    """
    if dry_run:
        return

    psycopg2.extras.execute_batch(cursor, sql, functions, page_size=200)


def insert_community_insights(cursor, layouts, dry_run=False):
    """
    Insert structure layouts into community_insights table if it exists.
    Uses (binary_name, insight_type, title) as a soft uniqueness check.
    """
    # Check if the table exists
    cursor.execute("""
        SELECT EXISTS (
            SELECT FROM pg_tables
            WHERE schemaname = 'public' AND tablename = 'community_insights'
        )
    """)
    if not cursor.fetchone()[0]:
        print("  WARNING: community_insights table does not exist, skipping structure layouts.")
        print("           Create it first if you want to store structure layout data.")
        return 0

    # Detect columns to handle schema variations
    cursor.execute("""
        SELECT column_name FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'community_insights'
        ORDER BY ordinal_position
    """)
    columns = {row[0] for row in cursor.fetchall()}

    count = 0
    for layout in layouts:
        if dry_run:
            count += 1
            continue

        # Build an insert appropriate for whatever columns exist
        # Minimum expected: some form of title/content/type columns
        if "insight_type" in columns and "title" in columns and "content" in columns:
            cursor.execute("""
                INSERT INTO community_insights (insight_type, title, content)
                VALUES ('algorithm_description', %s, %s)
                ON CONFLICT DO NOTHING
            """, (layout["title"], layout["content"]))
            count += 1
        else:
            print(f"  WARNING: community_insights schema mismatch, skipping: {layout['title']}")

    return count


def insert_function_hierarchy(cursor, families, dry_run=False):
    """
    Insert function families into d2_function_hierarchy table if it exists.
    """
    cursor.execute("""
        SELECT EXISTS (
            SELECT FROM pg_tables
            WHERE schemaname = 'public' AND tablename = 'd2_function_hierarchy'
        )
    """)
    if not cursor.fetchone()[0]:
        print("  WARNING: d2_function_hierarchy table does not exist, skipping function families.")
        print("           Create it first if you want to store function family data.")
        return 0

    # Detect columns
    cursor.execute("""
        SELECT column_name FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'd2_function_hierarchy'
        ORDER BY ordinal_position
    """)
    columns = {row[0] for row in cursor.fetchall()}

    count = 0
    for family in families:
        if dry_run:
            count += 1
            continue

        if "family_name" in columns and "description" in columns:
            ordinals_json = json.dumps(family.get("ordinals", []))
            cursor.execute("""
                INSERT INTO d2_function_hierarchy (family_name, description, ordinals)
                VALUES (%s, %s, %s::jsonb)
                ON CONFLICT DO NOTHING
            """, (family["family_name"], family["description"], ordinals_json))
            count += 1
        else:
            print(f"  WARNING: d2_function_hierarchy schema mismatch, skipping: {family['family_name']}")

    return count


# ---------------------------------------------------------------------------
# Main migration
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Migrate RE loop learnings from flat files into knowledge DB"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be migrated without writing to the database",
    )
    args = parser.parse_args()
    dry_run = args.dry_run

    if dry_run:
        print("=" * 60)
        print("DRY RUN MODE -- no database writes will be performed")
        print("=" * 60)
    else:
        print("=" * 60)
        print("MIGRATION: flat files -> knowledge DB")
        print("=" * 60)

    # ------------------------------------------------------------------
    # Read source files
    # ------------------------------------------------------------------

    learnings_text = None
    if LEARNINGS_PATH.exists():
        learnings_text = LEARNINGS_PATH.read_text(encoding="utf-8")
        print(f"\n[1/3] Read {LEARNINGS_PATH.name}: {len(learnings_text):,} chars")
    else:
        print(f"\n[1/3] SKIP: {LEARNINGS_PATH} not found")

    loop_state = None
    if LOOP_STATE_PATH.exists():
        with open(LOOP_STATE_PATH, "r", encoding="utf-8") as f:
            loop_state = json.load(f)
        print(f"[2/3] Read {LOOP_STATE_PATH.name}: version {loop_state.get('version')}")
    else:
        print(f"[2/3] SKIP: {LOOP_STATE_PATH} not found")

    community_data = None
    if COMMUNITY_NAMES_PATH.exists():
        with open(COMMUNITY_NAMES_PATH, "r", encoding="utf-8") as f:
            community_data = json.load(f)
        print(f"[3/3] Read {COMMUNITY_NAMES_PATH.name}: version {community_data.get('version')}")
    else:
        print(f"[3/3] SKIP: {COMMUNITY_NAMES_PATH} not found")

    # ------------------------------------------------------------------
    # Extract data
    # ------------------------------------------------------------------

    print("\n--- Extraction ---")

    # Ordinal mappings from learnings.md
    learnings_ordinals = []
    structure_layouts = []
    function_families = []
    if learnings_text:
        learnings_ordinals = extract_ordinal_mappings_from_learnings(learnings_text)
        structure_layouts = extract_structure_layouts(learnings_text)
        function_families = extract_function_families(learnings_text)
        print(f"  learnings.md -> {len(learnings_ordinals)} ordinal mappings")
        print(f"  learnings.md -> {len(structure_layouts)} structure layouts")
        print(f"  learnings.md -> {len(function_families)} function families")

    # Documented functions from loop_state.json
    documented_funcs = []
    if loop_state:
        documented_funcs = extract_documented_functions(loop_state)
        print(f"  loop_state.json -> {len(documented_funcs)} documented functions")

        # Breakdown by binary
        by_binary = {}
        for f in documented_funcs:
            key = f"{f['binary_name']}@{f['version']}"
            by_binary[key] = by_binary.get(key, 0) + 1
        for key, count in sorted(by_binary.items()):
            print(f"    {key}: {count}")

    # Community ordinal mappings
    community_ordinals = []
    if community_data:
        community_ordinals = extract_community_ordinal_mappings(community_data)
        print(f"  community_names.json -> {len(community_ordinals)} ordinal mappings")

        # Breakdown by DLL
        by_dll = {}
        for m in community_ordinals:
            by_dll[m["binary_name"]] = by_dll.get(m["binary_name"], 0) + 1
        for dll, count in sorted(by_dll.items()):
            print(f"    {dll}: {count}")

    # ------------------------------------------------------------------
    # Deduplication summary
    # ------------------------------------------------------------------

    total_ordinals = len(learnings_ordinals) + len(community_ordinals)
    print(f"\n--- Totals ---")
    print(f"  Ordinal mappings: {total_ordinals} "
          f"({len(learnings_ordinals)} from learnings, "
          f"{len(community_ordinals)} from community)")
    print(f"  Documented functions: {len(documented_funcs)}")
    print(f"  Structure layouts: {len(structure_layouts)}")
    print(f"  Function families: {len(function_families)}")

    if dry_run:
        print("\n--- Dry Run Summary ---")
        print(f"  Would upsert {total_ordinals} ordinal_mappings rows")
        print(f"  Would upsert {len(documented_funcs)} documented_functions rows")
        print(f"  Would insert {len(structure_layouts)} community_insights rows (if table exists)")
        print(f"  Would insert {len(function_families)} d2_function_hierarchy rows (if table exists)")

        # Show sample data
        if learnings_ordinals:
            print("\n  Sample ordinal mappings (learnings.md, first 5):")
            for m in learnings_ordinals[:5]:
                print(f"    {m['binary_name']}@{m['version']} "
                      f"ord {m['ordinal']}: {m['function_name']} "
                      f"[{m['source']}, conf={m['confidence']}]")

        if community_ordinals:
            print("\n  Sample ordinal mappings (community_names.json, first 5):")
            for m in community_ordinals[:5]:
                print(f"    {m['binary_name']}@{m['version']} "
                      f"ord {m['ordinal']}: {m['function_name']} "
                      f"[{m['source']}, conf={m['confidence']}]")

        if documented_funcs:
            print("\n  Sample documented functions (first 5):")
            for f in documented_funcs[:5]:
                print(f"    {f['binary_name']}@{f['version']} "
                      f"{f['address']}: {f['old_name']} -> {f['new_name']} "
                      f"(score={f['score']}, iter={f['iteration']})")

        if structure_layouts:
            print("\n  Structure layouts:")
            for s in structure_layouts:
                preview = s["content"][:80].replace("\n", " ")
                print(f"    {s['title']}: {preview}...")

        if function_families:
            print("\n  Function families (first 5):")
            for fam in function_families[:5]:
                print(f"    {fam['family_name']}: {len(fam['ordinals'])} ordinals")

        print("\nDry run complete. No database changes made.")
        return

    # ------------------------------------------------------------------
    # Write to database
    # ------------------------------------------------------------------

    if not total_ordinals and not documented_funcs and not structure_layouts:
        print("\nNothing to migrate.")
        return

    print("\n--- Database Migration ---")
    conn = connect_db()
    try:
        cursor = conn.cursor()

        # 1. Ordinal mappings: community first (lower confidence),
        #    then learnings (higher confidence, will win ON CONFLICT)
        if community_ordinals:
            print(f"  Upserting {len(community_ordinals)} community ordinal mappings...")
            upsert_ordinal_mappings(cursor, community_ordinals, dry_run=False)

        if learnings_ordinals:
            print(f"  Upserting {len(learnings_ordinals)} learnings ordinal mappings...")
            upsert_ordinal_mappings(cursor, learnings_ordinals, dry_run=False)

        # 2. Documented functions
        if documented_funcs:
            print(f"  Upserting {len(documented_funcs)} documented functions...")
            upsert_documented_functions(cursor, documented_funcs, dry_run=False)

        # 3. Structure layouts -> community_insights
        if structure_layouts:
            print(f"  Inserting {len(structure_layouts)} structure layouts...")
            n = insert_community_insights(cursor, structure_layouts, dry_run=False)
            if n:
                print(f"    Inserted {n} community_insights rows.")

        # 4. Function families -> d2_function_hierarchy
        if function_families:
            print(f"  Inserting {len(function_families)} function families...")
            n = insert_function_hierarchy(cursor, function_families, dry_run=False)
            if n:
                print(f"    Inserted {n} d2_function_hierarchy rows.")

        conn.commit()
        print("\nMigration committed successfully.")

        # Verification counts
        cursor.execute("SELECT COUNT(*) FROM ordinal_mappings")
        print(f"  ordinal_mappings total rows: {cursor.fetchone()[0]}")
        cursor.execute("SELECT COUNT(*) FROM documented_functions")
        print(f"  documented_functions total rows: {cursor.fetchone()[0]}")

    except Exception as e:
        conn.rollback()
        print(f"\nERROR: Migration failed, rolled back: {e}")
        raise
    finally:
        conn.close()

    print("\nDone.")


if __name__ == "__main__":
    main()
