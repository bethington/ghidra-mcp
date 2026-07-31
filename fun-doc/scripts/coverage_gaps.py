#!/usr/bin/env python3
"""Turn the live dispatcher table into a concrete in-game play checklist.

Why this exists. Every CONF_LIVE function that has a reimpl now has a shadow
dispatcher -- the stranded pool is drained -- so dispatchers are no longer the
constraint. What gates promotion is GAMEPLAY COVERAGE: a dispatcher that is
never called can never accrue evidence, and one called with a single repeated
input never clears the diversity floor. Measured 2026-07-30, only 115 of 183
dispatchers had recorded any distinct inputs at all.

Until now that coverage was unguided -- play happened, and we hoped the right
functions got hit. This converts "play more" into "do these specific things",
which matters because the play-driven loop is the mechanism that actually
works: every session so far has both promoted functions AND surfaced a real
reimpl defect with an exact counterexample (live shadow found all three; the
static offset audit found none -- see audit_reimpl_offsets.py's verdict).

Ordering is deliberate. The report leads with functions that are CLOSE to the
bar, because "needs 3 more distinct inputs" is a far cheaper win than "has
never been called once", and a checklist nobody finishes is worth nothing.

Read-only. Requires the game running with the oracle on :8790.

Usage:
    python -m scripts.coverage_gaps
    python -m scripts.coverage_gaps --top 15
"""

from __future__ import annotations

import argparse
import collections
import json
import os
import sys
import urllib.request
from pathlib import Path

_HERE = Path(__file__).resolve().parent.parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

import conf_ladder as L  # noqa: E402

ORACLE_URL = os.environ.get("D2DBG_MCP_URL", "http://127.0.0.1:8790").rstrip("/")

# Subsystem -> what a player actually has to DO to reach that code. Derived from
# the D2Common naming convention (prefix before the first underscore).
ACTIVITY = {
    "SKILLS": "cast a VARIETY of skills -- different trees, and both melee and "
              "ranged; each distinct skill id is a distinct input",
    "SKILL": "cast a variety of skills, including ones you rarely use",
    "MISSILE": "use PROJECTILE skills (bone spear, arrows, bolts) and let them "
               "hit walls, monsters and nothing at all",
    "MONSTER": "fight VARIED monster types -- normal, champion, unique and boss "
               "packs, and different acts if you can",
    "MON": "fight varied monster types across several areas",
    "ITEMS": "pick up, equip, unequip, sell, buy and drop items of many "
             "different TYPES and QUALITIES (normal/magic/rare/set/unique)",
    "ITEM": "handle many item types and qualities",
    "INV": "move items around the inventory, stash, belt and cube; equip and "
           "unequip; try items that do not fit",
    "DATATBLS": "mostly driven by whatever else you do -- item, skill and "
                "monster variety all widen these table lookups",
    "STAT": "level up, allocate stats, gain and lose buffs/curses, take damage",
    "STATS": "level up, allocate stats, gain and lose buffs and curses",
    "STATLIST": "gain and lose temporary effects (potions, shrines, curses)",
    "PATH": "MOVE a lot -- walk, run, teleport, get blocked by walls, path "
            "around obstacles",
    "DUNGEON": "change areas often; use waypoints and town portals",
    "DRLG": "enter NEW areas so the level generator runs",
    "ROOM": "move between rooms and areas",
    "UNIT": "interact with many entity kinds -- monsters, NPCs, objects, "
            "missiles, items on the ground",
    "UNITS": "interact with many entity kinds, including NPCs and objects",
    "PLAYER": "player actions -- equip, level, move, die and revive",
    "INVENTORY": "inventory, stash, belt and cube operations",
    "QUEST": "progress or complete quests",
    "SEED": "any gameplay -- RNG is exercised constantly",
    "COLLISION": "walk into walls, objects and monsters",
    "ROSTER": "party-related actions (may be unreachable in single player)",
}


def _get(path):
    with urllib.request.urlopen(f"{ORACLE_URL}/{path.lstrip('/')}", timeout=15) as r:
        return json.loads(r.read().decode("utf-8", "replace"))


# Many D2Common names carry no subsystem prefix at all (GetItemFlags,
# GetPathFlagBit3, IsMonsterInSpecialDeathMode). Prefix-only classification
# left those with no actionable advice, which defeats the point of a checklist,
# so fall back to the strongest keyword in the name. Order matters: the first
# match wins, so put the more specific words first.
_KEYWORDS = [
    ("Missile", "MISSILE"), ("Skill", "SKILLS"), ("Monster", "MONSTER"),
    ("Mon", "MONSTER"), ("Inventory", "INV"), ("Item", "ITEMS"),
    ("Path", "PATH"), ("Collision", "COLLISION"), ("Room", "ROOM"),
    ("Dungeon", "DUNGEON"), ("Level", "DRLG"), ("Stat", "STAT"),
    ("Unit", "UNIT"), ("Player", "PLAYER"), ("Quest", "QUEST"),
    ("Seed", "SEED"), ("Rand", "SEED"),
]


def subsystem(name):
    head = name.split("_")[0] if "_" in name else ""
    if head in ACTIVITY:
        return head
    for word, sub in _KEYWORDS:
        if word in name:
            return sub
    return head or name


def floor_for(d):
    argc = d.get("arg_count", 1)
    return L.effective_distinct_floor("CONF_BATTLETESTED",
                                      argc if isinstance(argc, int) and argc > 0 else 1)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--top", type=int, default=20,
                    help="how many near-the-bar functions to list")
    args = ap.parse_args()

    try:
        rows = _get("/dispatchers").get("dispatchers", []) or []
    except OSError as e:
        print(f"oracle unreachable at {ORACLE_URL}: {e}")
        print("Start the game (the guide reads LIVE counters) and re-run.")
        return 2
    if not rows:
        print("no dispatchers reported")
        return 2

    never, close, diverging, ready = [], [], [], []
    for d in rows:
        hits = d.get("hits", 0)
        di = d.get("distinct_inputs", 0) or 0
        need = floor_for(d)
        if d.get("divergences", 0):
            diverging.append(d)
        elif hits == 0:
            never.append(d)
        elif di >= need:
            ready.append(d)
        else:
            close.append((need - di, d, need, di, hits))

    print(f"COVERAGE GAPS -- {len(rows)} dispatchers\n")
    print(f"  meeting the diversity bar : {len(ready)}")
    print(f"  called but short of it    : {len(close)}")
    print(f"  NEVER CALLED              : {len(never)}")
    print(f"  currently diverging       : {len(diverging)}")

    if diverging:
        print("\nDIVERGING -- fix these before chasing coverage; a divergence is a")
        print("real counterexample and blocks promotion outright:")
        for d in diverging:
            print(f"   {d['name']:<40} div={d.get('divergences')} hits={d.get('hits')}")

    if close:
        print(f"\nCLOSEST TO PROMOTION (top {args.top}) -- cheapest wins, these are")
        print("already being called and just need more VARIED inputs:")
        # Sort by (gap, name): a bare sort falls through to comparing the dicts
        # whenever two functions need the same number of extra inputs.
        for gap, d, need, di, hits in sorted(
                close, key=lambda t: (t[0], t[1]["name"]))[:args.top]:
            act = ACTIVITY.get(subsystem(d["name"]), "vary your activity in this subsystem")
            print(f"   +{gap:<3} more  {d['name']:<38} ({di}/{need} distinct, {hits:,} hits)")
            print(f"              -> {act}")

    if never:
        print("\nNEVER CALLED -- grouped by what would reach them:")
        by_sub = collections.defaultdict(list)
        for d in never:
            by_sub[subsystem(d["name"])].append(d["name"])
        for sub, names in sorted(by_sub.items(), key=lambda kv: -len(kv[1])):
            act = ACTIVITY.get(sub, "unknown -- inspect callers to find the trigger")
            print(f"\n   {sub}  ({len(names)} function(s))")
            print(f"      DO: {act}")
            print(f"      {', '.join(sorted(names)[:8])}"
                  + (f", +{len(names) - 8} more" if len(names) > 8 else ""))

    # The bottom line: which ACTIVITIES unlock the most functions. Both buckets
    # count, weighted -- a function already close to the bar is a cheaper win
    # than one that has never been called, so it is worth more per unit of play.
    score = collections.Counter()
    reach = collections.defaultdict(int)
    for gap, d, _need, _di, _hits in close:
        s = subsystem(d["name"])
        score[s] += 2 if gap <= 5 else 1
        reach[s] += 1
    for d in never:
        s = subsystem(d["name"])
        score[s] += 1
        reach[s] += 1

    print("\n" + "=" * 68)
    print("ACTION PLAN -- do these, most valuable first")
    print("=" * 68)
    for i, (sub, _pts) in enumerate(score.most_common(6), 1):
        act = ACTIVITY.get(sub, "vary your activity here")
        print(f"\n{i}. {sub}  ({reach[sub]} function(s) would benefit)")
        print(f"   {act}")

    print("\nAfter a session, re-run this, then battletest_promoter.py to bank it.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
