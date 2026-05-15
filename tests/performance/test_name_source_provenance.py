"""Storage-layer tests for name-source provenance (#204).

Three tests check the schema migration + Repository write path:

  * Default `name_source = 'scan'` is applied on insert
  * `update_function_fields(name_source='propagation', ...)` is honored
    (i.e. the field made it into `_UPDATABLE_WORKFLOW_FIELDS`)
  * Round-trip through `_state_dict_from_repo` preserves provenance so
    the legacy dict-style consumers in fun_doc.py see it

Plus three tests for the `backfill_name_source.py` CLI:

  * Dry-run is read-only
  * `--name-pattern` regex matching against the current name field
  * `--apply` writes the expected fields

All tests use a fresh SQLite Repository under `tmp_path` — they never
touch the user's `fun-doc/state.db`. They depend on the v5.10 migration
(`0003_name_source.sql`) having been applied; `bootstrap_schema()` runs
that automatically on the test repo.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest


_FUNDOC_DIR = Path(__file__).resolve().parent.parent.parent / "fun-doc"
if str(_FUNDOC_DIR) not in sys.path:
    sys.path.insert(0, str(_FUNDOC_DIR))


@pytest.fixture
def tmp_repo(tmp_path):
    """Build a fresh SQLite Repository against a tmp_path file."""
    from storage import make_repository, StorageConfig

    db_path = tmp_path / "state.db"
    cfg = StorageConfig(backend="sqlite", url=f"sqlite:///{db_path}", schema=None)
    repo = make_repository(cfg)
    repo.bootstrap_schema()
    return repo


def _sample_row(**overrides):
    base = {
        "program_path": "/test/prog",
        "binary_name": "prog",
        "version": "1.13d",
        "address": "10001000",
        "name": "TestFunc",
        "score": 50,
        "fixable": 10.0,
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# Schema defaults
# ---------------------------------------------------------------------------

def test_migration_applies_name_source_default(tmp_repo):
    """A row inserted without `name_source` gets the schema default
    `'scan'` (not NULL). This is what the migration's
    `DEFAULT 'scan'` clause guarantees, and the selector skip rule
    only fires on `'propagation'`, so a NULL default would silently
    leak pre-migration rows through the gate."""
    tmp_repo.upsert_function(_sample_row())
    row = tmp_repo.get_function("/test/prog", "10001000")
    assert row is not None
    assert row.get("name_source") == "scan"
    # Companion fields stay NULL until explicitly set.
    assert row.get("name_source_binary") is None
    assert row.get("name_confidence") is None


def test_upsert_can_set_propagation_provenance(tmp_repo):
    """Explicit name_source set on insert is honored — the propagation
    scripts will use this path to mark new rows as they apply names."""
    tmp_repo.upsert_function(_sample_row(
        name_source="propagation",
        name_source_binary="/Vanilla/1.13d/D2Common.dll",
        name_confidence=0.3,
    ))
    row = tmp_repo.get_function("/test/prog", "10001000")
    assert row["name_source"] == "propagation"
    assert row["name_source_binary"] == "/Vanilla/1.13d/D2Common.dll"
    assert row["name_confidence"] == pytest.approx(0.3)


# ---------------------------------------------------------------------------
# Partial update path (the backfill / worker write path)
# ---------------------------------------------------------------------------

def test_update_function_fields_accepts_name_source(tmp_repo):
    """`update_function_fields(name_source='propagation', ...)` must
    actually write the field. The defensive `_UPDATABLE_WORKFLOW_FIELDS`
    set filters out unknown keys — if the new fields weren't added to
    the allowlist this would silently drop the update."""
    tmp_repo.upsert_function(_sample_row())
    ok = tmp_repo.update_function_fields(
        program_path="/test/prog",
        address="10001000",
        name_source="propagation",
        name_source_binary="/source/binary.dll",
        name_confidence=0.42,
    )
    assert ok is True

    row = tmp_repo.get_function("/test/prog", "10001000")
    assert row["name_source"] == "propagation"
    assert row["name_source_binary"] == "/source/binary.dll"
    assert row["name_confidence"] == pytest.approx(0.42)


def test_update_function_fields_partial_update_preserves_others(tmp_repo):
    """A partial update touching only name_source must not nuke
    name_source_binary or name_confidence (and vice versa). Repository
    semantics are UPSERT-PATCH, not REPLACE."""
    tmp_repo.upsert_function(_sample_row(
        name_source="propagation",
        name_source_binary="/source/binary.dll",
        name_confidence=0.9,
    ))
    # Patch only the confidence.
    tmp_repo.update_function_fields(
        program_path="/test/prog",
        address="10001000",
        name_confidence=0.95,
    )
    row = tmp_repo.get_function("/test/prog", "10001000")
    assert row["name_source"] == "propagation"
    assert row["name_source_binary"] == "/source/binary.dll"
    assert row["name_confidence"] == pytest.approx(0.95)


# ---------------------------------------------------------------------------
# Backfill CLI
# ---------------------------------------------------------------------------

@pytest.fixture
def backfill_with_repo(monkeypatch, tmp_repo):
    """Patch the backfill module's repo factory so the CLI uses our
    tmp_path SQLite instead of the user's real state.db."""
    from scripts import backfill_name_source

    monkeypatch.setattr(backfill_name_source, "make_repository", lambda cfg: tmp_repo)
    monkeypatch.setattr(backfill_name_source, "resolve_config", lambda block: None)
    return backfill_name_source, tmp_repo


def _seed_propagated_candidates(repo):
    """Seed three propagated D2-style names + one user function."""
    repo.upsert_function(_sample_row(
        address="10000001", name="DATATBLS_SerializeJsonValue",
    ))
    repo.upsert_function(_sample_row(
        address="10000002", name="ROOM_GetTileDataAtFloor",
    ))
    repo.upsert_function(_sample_row(
        address="10000003", name="NET_ClearAsyncCallbacks",
    ))
    repo.upsert_function(_sample_row(
        address="10000004", name="BHRenderOverlay",
    ))


def test_backfill_dry_run_is_read_only(backfill_with_repo, capsys):
    """Without --apply, the script prints a summary but writes nothing."""
    backfill_mod, repo = backfill_with_repo
    _seed_propagated_candidates(repo)

    rc = backfill_mod.main([
        "--program", "/test/prog",
        "--name-pattern", "^(DATATBLS|ROOM|NET)_",
        "--source-binary", "/Vanilla/1.13d/D2Common.dll",
    ])
    assert rc == 0

    out = capsys.readouterr().out
    assert "Matched 3 row(s)" in out
    assert "Dry-run" in out

    # No writes happened — all three rows still have the default scan source.
    for addr in ("10000001", "10000002", "10000003"):
        row = repo.get_function("/test/prog", addr)
        assert row["name_source"] == "scan"


def test_backfill_apply_writes_propagation(backfill_with_repo, capsys):
    backfill_mod, repo = backfill_with_repo
    _seed_propagated_candidates(repo)

    rc = backfill_mod.main([
        "--program", "/test/prog",
        "--name-pattern", "^(DATATBLS|ROOM|NET)_",
        "--source-binary", "/Vanilla/1.13d/D2Common.dll",
        "--apply",
    ])
    assert rc == 0
    out = capsys.readouterr().out
    assert "Wrote 3 row(s)" in out

    for addr in ("10000001", "10000002", "10000003"):
        row = repo.get_function("/test/prog", addr)
        assert row["name_source"] == "propagation"
        assert row["name_source_binary"] == "/Vanilla/1.13d/D2Common.dll"

    # BH user function untouched.
    user_row = repo.get_function("/test/prog", "10000004")
    assert user_row["name_source"] == "scan"


def test_backfill_from_json_input(backfill_with_repo, tmp_path):
    """JSON-driven backfill: list of {program, address} records."""
    backfill_mod, repo = backfill_with_repo
    _seed_propagated_candidates(repo)

    manifest = tmp_path / "propagated.json"
    manifest.write_text(json.dumps([
        {"program": "/test/prog", "address": "10000001"},
        {"program": "/test/prog", "address": "10000004"},  # explicit user override
    ]))

    rc = backfill_mod.main([
        "--from-json", str(manifest),
        "--source-binary", "/Vanilla/1.13d/D2Common.dll",
        "--apply",
    ])
    assert rc == 0

    # Only the two addresses in the manifest get touched.
    assert repo.get_function("/test/prog", "10000001")["name_source"] == "propagation"
    assert repo.get_function("/test/prog", "10000004")["name_source"] == "propagation"
    assert repo.get_function("/test/prog", "10000002")["name_source"] == "scan"
    assert repo.get_function("/test/prog", "10000003")["name_source"] == "scan"


def test_backfill_requires_source_binary_for_propagation(backfill_with_repo):
    """--name-source=propagation without --source-binary should fail
    fast — losing the source binary destroys the forensic trail."""
    backfill_mod, _ = backfill_with_repo
    with pytest.raises(SystemExit):
        backfill_mod.main([
            "--program", "/test/prog",
            "--name-pattern", "^DATATBLS_",
            "--name-source", "propagation",
            # no --source-binary
        ])


def test_backfill_confidence_must_be_in_range(backfill_with_repo):
    """--confidence outside [0, 1] should fail at argparse time."""
    backfill_mod, _ = backfill_with_repo
    with pytest.raises(SystemExit):
        backfill_mod.main([
            "--program", "/test/prog",
            "--name-pattern", "^DATATBLS_",
            "--source-binary", "/x.dll",
            "--confidence", "1.5",
        ])
