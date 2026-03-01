#!/usr/bin/env python3
"""
Build a local community name cache for D2 ordinal->name mappings.

Fetches and parses:
- haxifix/PlugY D2Funcs.h - F8() macro format with multi-version ordinals
- D2MOO naming conventions - DATATBLS_, STATLIST_, ITEMS_ prefixes

Output: workflows/community_names.json

Version columns in F8() macros (8 versions):
  1.09b, 1.09d, 1.10, 1.11, 1.11b, 1.12, 1.13c, 1.13d
"""

import json
import re
import sys
from pathlib import Path

try:
    import requests
except ImportError:
    print("ERROR: 'requests' module required. Install with: pip install requests")
    sys.exit(1)

CACHE_FILE = Path(__file__).parent.parent / "workflows" / "community_names.json"

# Version column indices in F8() macro (0-based after DLL name)
VERSION_NAMES = ["1.09b", "1.09d", "1.10", "1.11", "1.11b", "1.12", "1.13c", "1.13d"]

# DLL name normalization
DLL_NAMES = {
    "D2Common": "D2Common.dll",
    "D2Client": "D2Client.dll",
    "D2Game": "D2Game.dll",
    "D2Lang": "D2Lang.dll",
    "D2CMP": "D2CMP.dll",
    "D2Win": "D2Win.dll",
    "D2gfx": "D2Gfx.dll",
    "D2Net": "D2Net.dll",
    "D2Sound": "D2Sound.dll",
    "D2Multi": "D2Multi.dll",
    "D2Launch": "D2Launch.dll",
    "Fog": "Fog.dll",
    "Storm": "Storm.dll",
}


def fetch_url(url, description):
    """Fetch a URL with error handling."""
    print(f"  Fetching {description}...")
    try:
        resp = requests.get(url, timeout=30)
        resp.raise_for_status()
        return resp.text
    except Exception as e:
        print(f"  WARNING: Failed to fetch {description}: {e}")
        return None


def parse_d2funcs_f8(text):
    """Parse haxifix D2Funcs.h F8() macros for multi-version ordinal mappings.

    Format: F8(STD, DLL, ord1, ord2, ..., ord8, addr, return_type, name, (params));
    Example: F8(STD,  D2Common,10057,10057,10057,10332,11021,10511,10826,10691, 21A1B0, DWORD, D2GetLevelID, (Room* ptRoom));

    Also parses commented-out D2S() lines:
    Format: //D2S(DLL,ordinal, return_type, name, (params));
    """
    # result[dll][version][ordinal] = {"name": ..., "source": ...}
    result = {}

    if not text:
        return result

    for line in text.split('\n'):
        stripped = line.strip()

        # Parse F8() macro lines
        # F8(CALL_CONV, DLL, o1, o2, o3, o4, o5, o6, o7, o8, addr, ret, name, (params))
        m = re.match(
            r'F8\(\w+,\s*(\w+),\s*'  # call_conv, DLL
            r'(\d+),\s*(\d+),\s*(\d+),\s*(\d+),\s*'  # ord 1-4
            r'(\d+),\s*(\d+),\s*(\d+),\s*(\d+),\s*'  # ord 5-8
            r'[\da-fA-F]+,\s*'  # address (hex, skip)
            r'[\w*\s]+,\s*'  # return type (skip)
            r'(\w+)',  # function name
            stripped
        )
        if m:
            dll_raw = m.group(1)
            ordinals = [m.group(i) for i in range(2, 10)]  # groups 2-9
            func_name = m.group(10)

            dll = DLL_NAMES.get(dll_raw, dll_raw + ".dll")

            for i, ordinal in enumerate(ordinals):
                if ordinal == "00000":
                    continue  # Not present in this version
                version = VERSION_NAMES[i]
                result.setdefault(dll, {}).setdefault(version, {})[ordinal] = {
                    "name": func_name,
                    "source": "PlugY/D2Funcs.h"
                }
            continue

        # Parse commented D2S() lines
        # //D2S(D2Common,10001, DWORD, D2GetActIDFromLevel, (DWORD levelID));
        m = re.match(
            r'//\s*D2S\(\s*(\w+),\s*(\d+),\s*'  # DLL, ordinal
            r'[\w*\s]+,\s*'  # return type
            r'(\w+)',  # function name
            stripped
        )
        if m:
            dll_raw = m.group(1)
            ordinal = m.group(2)
            func_name = m.group(3)

            if ordinal == "00000" or func_name.endswith(ordinal):
                continue  # Skip unnamed (D2Common10242 etc.)

            dll = DLL_NAMES.get(dll_raw, dll_raw + ".dll")

            # D2S lines don't specify version, assume all versions
            for version in VERSION_NAMES:
                result.setdefault(dll, {}).setdefault(version, {})[ordinal] = {
                    "name": func_name,
                    "source": "PlugY/D2Funcs.h (D2S)"
                }

    return result


def build_cache():
    """Build the community name cache from all sources."""
    print("Building community name cache...")

    cache = {
        "version": 2,
        "description": "Community ordinal->name mappings for Diablo II DLLs",
        "sources_fetched": [],
        "versions": VERSION_NAMES,
        "dlls": {}
    }

    # 1. haxifix/PlugY D2Funcs.h - primary source (F8 macro format)
    d2funcs_url = "https://raw.githubusercontent.com/haxifix/PlugY/master/Commons/D2Funcs.h"
    d2funcs_text = fetch_url(d2funcs_url, "haxifix/PlugY D2Funcs.h")

    if d2funcs_text:
        cache["sources_fetched"].append("haxifix/PlugY/D2Funcs.h")
        parsed = parse_d2funcs_f8(d2funcs_text)

        for dll, versions in parsed.items():
            cache["dlls"].setdefault(dll, {})
            for version, mappings in versions.items():
                cache["dlls"][dll].setdefault(version, {}).update(mappings)

            # Summary per DLL
            total = sum(len(v) for v in versions.values())
            unique_names = set()
            for v in versions.values():
                for entry in v.values():
                    unique_names.add(entry["name"])
            print(f"    {dll}: {len(unique_names)} unique functions across {len(versions)} versions ({total} total mappings)")

    # 2. D2MOO naming conventions (prefix patterns, not ordinals)
    d2moo_info = {
        "D2Common.dll": {
            "naming_conventions": {
                "DATATBLS_": "Data table functions (DataTbls.cpp)",
                "STATLIST_": "Stat list operations (D2StatList.cpp)",
                "ITEMS_": "Item functions (Items/)",
                "UNITS_": "Unit functions",
                "SKILLS_": "Skill functions",
                "DRLG_": "Level generation (Drlg/)",
                "PATH_": "Pathfinding functions",
                "COLLISION_": "Collision functions",
                "DUNGEON_": "Dungeon/room functions",
                "QUEST_": "Quest functions",
                "INVENTORY_": "Inventory functions",
                "MONSTER_": "Monster functions",
                "MISSILE_": "Missile functions",
            }
        }
    }
    cache["naming_conventions"] = d2moo_info
    cache["sources_fetched"].append("D2MOO (naming conventions)")

    # Write cache
    total_ordinals = 0
    for dll_data in cache["dlls"].values():
        for version_data in dll_data.values():
            total_ordinals += len(version_data)
    print(f"\nTotal ordinal mappings cached: {total_ordinals}")
    print(f"DLLs covered: {list(cache['dlls'].keys())}")

    CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(CACHE_FILE, 'w') as f:
        json.dump(cache, f, indent=2)

    print(f"Cache written to: {CACHE_FILE}")
    return cache


def lookup(dll, ordinal, version=None):
    """Look up a community name for a given DLL and ordinal.

    If version is specified, look up in that version only.
    Otherwise, return all version matches.
    """
    if not CACHE_FILE.exists():
        print("Cache not found. Run build_community_cache.py first.")
        return None

    with open(CACHE_FILE) as f:
        cache = json.load(f)

    dll_data = cache.get("dlls", {}).get(dll, {})

    if version:
        version_data = dll_data.get(version, {})
        return version_data.get(str(ordinal))
    else:
        # Return matches across all versions
        matches = {}
        for ver, ver_data in dll_data.items():
            entry = ver_data.get(str(ordinal))
            if entry:
                matches[ver] = entry
        return matches if matches else None


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "lookup":
        # Usage: python build_community_cache.py lookup D2Common.dll 10600
        # Usage: python build_community_cache.py lookup D2Common.dll 10600 1.13d
        if len(sys.argv) >= 4:
            version = sys.argv[4] if len(sys.argv) >= 5 else None
            result = lookup(sys.argv[2], sys.argv[3], version)
            if result:
                print(json.dumps(result, indent=2))
            else:
                print("Not found")
        else:
            print("Usage: python build_community_cache.py lookup <dll> <ordinal> [version]")
            print("Versions: " + ", ".join(VERSION_NAMES))
    else:
        build_cache()
