# fun-doc/archive/

Demonstrably-stale recovery artifacts moved out of `fun-doc/` so the
working tree stays focused on live state. Nothing here is read by the
dashboard, worker, or test fixtures — these are corrupt/truncated
snapshots and pre-cleanup backups kept only so a future "what did the
state.json look like at X date" question has an answer.

Each artifact is gitignored (see `.gitignore` `fun-doc/archive/`). Move
freely between machines or delete entirely when confident the data is
no longer needed for forensics.

## What's here

| File | When | Why |
| --- | --- | --- |
| `state.json.before-recovered-cleanup-20260503-155200` | 2026-05-03 | Snapshot taken before the May 3 cleanup pass — kept in case the cleanup removed something useful. |
| `state.json.corrupt-20260413-081430` | 2026-04-13 | The state.json that was found corrupt on April 13; the dashboard recovered from `state.json.bak`. |
| `state.json.truncated-20260503-2237` | 2026-05-03 | A 132-byte truncation that triggered the retry/rotate path. |
| `ghidra_http.jsonl.1.pre-rotation-20260514` | 2026-05-14 | The pre-rotation 1.03 GB Ghidra HTTP call log. When v5.10's `log_rotation.py` landed it correctly rotated the over-cap file to `.jsonl.1`; archived here so the working tree wasn't sitting on 1 GB of forensic data the rotation system would have evicted in ~20 days anyway. |

## Live state stays in fun-doc/

`fun-doc/state.db` (SQLite) is the runtime path as of v5.8.0.
`fun-doc/state.json` is read only by `scripts/migrate_state_to_sql.py`
and is no longer written at runtime; it stays in `fun-doc/` rather than
here because the migration script paths are still wired to that
location.

## Why a separate directory and not just `.gitignore`?

Both these artifacts are already gitignored individually. The separate
directory mainly helps disk-space accounting (`du -sh fun-doc/archive/`
gives you the exact recoverable size at a glance — ~180 MB at archive
creation) and signals intent: "these files are dead, the live ones are
in the parent directory."
