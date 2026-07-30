"""priority_queue.json config writes must merge, not clobber.

save_priority_queue() writes the whole file from the caller's in-memory snapshot,
which made every writer a last-writer-wins clobberer. Live consequence: setting
`globals_audit_provider` through the dashboard was silently reverted to None by a
concurrent `fun_doc.py --assess` subprocess that had loaded the queue BEFORE the
edit and saved it back after. No error, no log line -- the setting simply vanished,
and it was only caught because a worker started afterwards with the wrong policy.

Offline: pure file I/O, no Ghidra, no network.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

FUN_DOC = Path(__file__).parent.parent.parent / "fun-doc"
sys.path.insert(0, str(FUN_DOC))

import fun_doc as fd  # noqa: E402


@pytest.fixture
def queue_file(tmp_path, monkeypatch):
    """Point fun_doc's queue path at a scratch file."""
    p = tmp_path / "priority_queue.json"
    p.write_text(json.dumps({"pinned": [], "config": {"good_enough_score": 80}}),
                 encoding="utf-8")
    monkeypatch.setattr(fd, "PRIORITY_QUEUE_FILE", p)
    return p


def _disk(p):
    return json.loads(p.read_text(encoding="utf-8"))["config"]


def test_stale_writer_does_not_clobber_a_concurrent_edit(queue_file):
    """The exact production sequence that lost globals_audit_provider."""
    # A long-running CLI process loads the queue...
    stale = fd.load_priority_queue()

    # ...meanwhile the dashboard sets a new value and saves.
    live = fd.load_priority_queue()
    live["config"]["globals_audit_provider"] = "claude"
    fd.save_priority_queue(live)
    assert _disk(queue_file)["globals_audit_provider"] == "claude"

    # Now the stale process saves its own unrelated change.
    stale["config"]["good_enough_score"] = 90
    fd.save_priority_queue(stale)

    cfg = _disk(queue_file)
    assert cfg["good_enough_score"] == 90            # the stale writer's own edit lands
    assert cfg["globals_audit_provider"] == "claude"  # and does NOT eat the other one


def test_writer_can_still_clear_a_value_it_owns(queue_file):
    """Merging must not make settings un-clearable: an explicit change to None is
    an opinion, not an absence of one."""
    q = fd.load_priority_queue()
    q["config"]["globals_audit_provider"] = "claude"
    fd.save_priority_queue(q)

    q2 = fd.load_priority_queue()
    q2["config"]["globals_audit_provider"] = None
    fd.save_priority_queue(q2)
    assert _disk(queue_file)["globals_audit_provider"] is None


def test_last_explicit_write_wins_on_the_same_key(queue_file):
    """Two writers touching the SAME key is a genuine conflict; last write wins.
    The merge only protects keys a writer never touched."""
    a = fd.load_priority_queue()
    b = fd.load_priority_queue()
    a["config"]["good_enough_score"] = 85
    fd.save_priority_queue(a)
    b["config"]["good_enough_score"] = 95
    fd.save_priority_queue(b)
    assert _disk(queue_file)["good_enough_score"] == 95


def test_keys_added_by_another_writer_survive(queue_file):
    stale = fd.load_priority_queue()
    live = fd.load_priority_queue()
    live["config"]["brand_new_key"] = "kept"
    fd.save_priority_queue(live)

    stale["config"]["good_enough_score"] = 70
    fd.save_priority_queue(stale)
    assert _disk(queue_file)["brand_new_key"] == "kept"


def test_baseline_never_reaches_disk(queue_file):
    q = fd.load_priority_queue()
    assert fd._CONFIG_BASELINE_KEY in q          # present in memory for the merge
    fd.save_priority_queue(q)
    on_disk = json.loads(queue_file.read_text(encoding="utf-8"))
    assert fd._CONFIG_BASELINE_KEY not in on_disk


def test_hand_built_queue_without_baseline_still_saves(queue_file):
    """Callers that build a queue dict themselves (no load) must keep working."""
    fd.save_priority_queue({"pinned": [], "config": {"good_enough_score": 60}})
    assert _disk(queue_file)["good_enough_score"] == 60


def test_repeated_saves_from_one_dict_keep_merging(queue_file):
    """A caller that loads once and saves MANY times must stay protected.

    The first version of this merge popped the baseline on save, so the second
    save onwards silently reverted to last-writer-wins. select_candidates does
    exactly this -- it takes a `queue` from its caller and saves it repeatedly --
    and it ate globals_audit_provider a third time with the merge already in place.
    """
    stale = fd.load_priority_queue()
    fd.save_priority_queue(stale)                 # save #1 consumed the baseline before

    live = fd.load_priority_queue()
    live["config"]["globals_audit_provider"] = "claude"
    fd.save_priority_queue(live)

    stale["config"]["good_enough_score"] = 91     # save #2 from the same dict
    fd.save_priority_queue(stale)

    cfg = _disk(queue_file)
    assert cfg["good_enough_score"] == 91
    assert cfg["globals_audit_provider"] == "claude"


def test_baseline_survives_a_save_for_reuse(queue_file):
    q = fd.load_priority_queue()
    fd.save_priority_queue(q)
    assert fd._CONFIG_BASELINE_KEY in q           # re-armed, not consumed
    assert fd._CONFIG_BASELINE_KEY not in json.loads(
        queue_file.read_text(encoding="utf-8"))   # still never on disk
