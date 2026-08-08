"""A synthetic Ghidra program, served through ``conformance_dashboard._get``.

The dashboard read layer talks to the Ghidra plugin through exactly two
functions -- ``conformance_dashboard._get`` and ``._post`` -- so replacing
those two gives a complete, hermetic backend with no plugin, no JVM and no
project on disk.

Why a hand-built corpus rather than a recording of a real one
-------------------------------------------------------------
Because the assertions that matter are *arithmetic*, and arithmetic needs
known operands. Every historical bar bug in this project was a numerator
covering a wider population than its denominator (the ``326700%`` and
``228600%`` bars, the 105.3%/172.6% matrix overcount). A recorded corpus
lets you assert "the page shows what the API said"; it cannot tell you
whether either is RIGHT. This corpus is built so the right answer is known
in advance:

    50 defined functions
     10 carry LIB_CRT              -> excluded from every denominator
     40 in scope
     28 of the 40 carry a DOC_ rung
     18 of the 40 carry a CONF_ rung
     30 of the 40 carry a COMPLETE_ band
     12 in scope, never evaluated  -> the matrix `none`/`none` cell

    20 image globals
      2 marked library data (Scope) -> excluded
     18 in scope
     11 carry a Complete band
      4 carry the REVIEWED trust bit

so ``in_scope`` is 40 and 18, the matrix `none`/`none` cell must be exactly
12, and no bar can exceed 100% unless something subtracts the library set
from one side of the division and not the other.

Faults
------
``FakeGhidra.fail_with`` makes every subsequent call raise, which is how the
"Ghidra went away mid-render" path is exercised. ``drop_envelope`` returns
the pre-7.0.0 *string* shape instead of the record envelope, reproducing the
regression where both inventories silently returned zero rows for days.
"""

from __future__ import annotations

import json
from typing import Any

# --------------------------------------------------------------------------
# corpus geometry -- addresses are bare lowercase hex, as the plugin emits
# --------------------------------------------------------------------------

IMAGE_BASE = 0x6FD50000
IMAGE_END = 0x6FD90000

N_FUNCTIONS = 53
N_LIBRARY = 10
# Graph-inferred exclusions (scope_graph's SCOPE_EXCLUDED). A SEPARATE
# population on purpose: the panels must be able to report "identified library"
# apart from "inferred out of scope", so a corpus where the two are the same set
# would let a fold-them-together bug pass. These are named like game code,
# because that is the case that matters -- 143 of PD2_EXT's CRT survivors had
# already been renamed `UNIT_*`/`STRING_*` by documentation workers, which is
# exactly why the sweep keys on references instead of names.
N_SCOPE_EXCLUDED = 3
N_IN_SCOPE = N_FUNCTIONS - N_LIBRARY - N_SCOPE_EXCLUDED  # 40, unchanged


N_GLOBALS = 20
N_GLOBALS_EXCLUDED = 2
N_GLOBALS_IN_SCOPE = N_GLOBALS - N_GLOBALS_EXCLUDED  # 18

PROGRAM = "/testing/fake/Fake.dll"


def _fn_addr(i: int) -> str:
    return "%x" % (IMAGE_BASE + 0x1000 + i * 0x40)


def _glob_addr(i: int) -> str:
    return "%x" % (IMAGE_BASE + 0x20000 + i * 0x10)


class FakeGhidra:
    """An in-memory program with a known, checkable shape."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, dict]] = []
        self.writes: list[tuple[str, dict]] = []
        self.fail_with: Exception | None = None
        self.drop_envelope = False
        self._build()

    # -- corpus ------------------------------------------------------------

    def _build(self) -> None:
        self.functions: list[dict] = [
            {"address": _fn_addr(i), "name": f"FakeFunction{i:02d}"} for i in range(N_FUNCTIONS)
        ]
        # The last N_LIBRARY are the linked runtime. Naming them like real CRT
        # matters: `library_code_detector` and doc_lint both look at names, and
        # a corpus whose "library" functions are named FakeFunction4x would let
        # a name-based bug pass.
        crt_names = [
            "_strlen", "_memset", "_memcpy", "_malloc", "_free",
            "__security_check_cookie", "_atol", "_sprintf", "_qsort", "__ld12tod",
        ]
        for offset, name in enumerate(crt_names):
            self.functions[N_IN_SCOPE + offset]["name"] = name
        # The graph-inferred block sits after the identified runtime and wears
        # GAME-STYLE names, since that is the population names cannot catch.
        for offset, name in enumerate(("UNIT_GetUnitFlags2",
                                       "MEMMGR_DetectSimdCapabilities",
                                       "STRING_CopyBounded")):
            self.functions[N_IN_SCOPE + N_LIBRARY + offset]["name"] = name

        in_scope = [f["address"] for f in self.functions[:N_IN_SCOPE]]
        library = [f["address"] for f in
                   self.functions[N_IN_SCOPE:N_IN_SCOPE + N_LIBRARY]]
        scope_excluded = [f["address"] for f in
                          self.functions[N_IN_SCOPE + N_LIBRARY:]]

        # tag -> addresses. Rungs are mutually exclusive on each axis, which is
        # what `matrix()` assumes when it takes the FIRST matching rung.
        self.tags: dict[str, list[str]] = {
            "LIB_CRT": library,
            "SCOPE_EXCLUDED": scope_excluded,
            "DOC_VERIFIED": in_scope[0:6],
            "DOC_REVIEWED": in_scope[6:16],
            "DOC_DRAFT": in_scope[16:28],
            "CONF_REGRESSION": in_scope[0:2],
            "CONF_BATTLETESTED": in_scope[2:5],
            "CONF_LIVE": in_scope[5:9],
            "CONF_VECTORS": in_scope[9:13],
            "CONF_DRAFT": in_scope[13:18],
            "COMPLETE_100": in_scope[0:5],
            "COMPLETE_95": in_scope[5:12],
            "COMPLETE_90": in_scope[12:22],
            "COMPLETE_80": in_scope[22:30],
        }

        # Globals: text rows in the plugin's list_globals shape.
        self.globals: list[str] = []
        for i in range(N_GLOBALS):
            typed = "dword" if i % 3 else "undefined4"
            self.globals.append(
                f"g_dwFakeGlobal{i:02d} @ {_glob_addr(i)} [DATA] ({typed}) xrefs={i}"
            )
        # One address carries a second label, so the "one row per address"
        # invariant is actually exercised (D2Client had up to seven).
        self.globals.append(f"g_dwAliasOfZero @ {_glob_addr(0)} [DATA] (dword) xrefs=1")

        self.properties: dict[str, dict[str, str]] = {
            # library data, excluded from the globals denominator
            "Scope": {_glob_addr(i): "LIB" for i in range(N_GLOBALS_EXCLUDED)},
            "Complete": {
                **{_glob_addr(i): "COMPLETE_100" for i in range(2, 5)},
                **{_glob_addr(i): "COMPLETE_95" for i in range(5, 8)},
                **{_glob_addr(i): "COMPLETE_90" for i in range(8, 11)},
                **{_glob_addr(i): "COMPLETE_80" for i in range(11, 13)},
            },
            "Doc": {_glob_addr(i): "REVIEWED" for i in range(2, 6)},
        }

        self.segments = [
            {"name": ".text", "start": "%x" % IMAGE_BASE, "end": "%x" % (IMAGE_BASE + 0x20000)},
            {"name": ".data", "start": "%x" % (IMAGE_BASE + 0x20000), "end": "%x" % IMAGE_END},
        ]

        self.program_options = {
            "Conformance.summary": json.dumps(
                {
                    "in_scope": N_IN_SCOPE,
                    # The sync tool's own count -- both exclusion families, since
                    # `in_scope` is defined-minus-everything-out-of-scope.
                    "excluded_lib": N_LIBRARY + N_SCOPE_EXCLUDED,
                    "total_all": N_FUNCTIONS,
                    "generated": "2026-08-03T00:00:00Z",
                }
            )
        }

    # -- known-good answers, for tests to assert against -------------------

    @property
    def expected_evaluated(self) -> int:
        """In-scope functions carrying a DOC_ or CONF_ rung."""
        doc = set(self.tags["DOC_VERIFIED"] + self.tags["DOC_REVIEWED"] + self.tags["DOC_DRAFT"])
        conf = set(
            self.tags["CONF_REGRESSION"]
            + self.tags["CONF_BATTLETESTED"]
            + self.tags["CONF_LIVE"]
            + self.tags["CONF_VECTORS"]
            + self.tags["CONF_DRAFT"]
        )
        return len(doc | conf)

    @property
    def expected_untriaged(self) -> int:
        return N_IN_SCOPE - self.expected_evaluated

    # -- transport ---------------------------------------------------------

    def get(self, path: str, **params: Any) -> Any:
        if self.fail_with is not None:
            raise self.fail_with
        self.calls.append((path, params))
        handler = getattr(self, "_get" + path.replace("/", "_"), None)
        if handler is None:
            # Unknown endpoints must not silently return {} -- a dashboard
            # panel reading an endpoint this fake does not model would then
            # render "no data" and its test would pass against nothing.
            raise AssertionError(
                f"FakeGhidra has no model for GET {path} (params={params!r}). "
                f"Add one rather than letting the panel read an empty result."
            )
        return handler(**params)

    def post(self, path: str, data: dict | None = None, **_: Any) -> dict:
        if self.fail_with is not None:
            raise self.fail_with
        self.writes.append((path, dict(data or {})))
        return {"success": True}

    # -- endpoint models ---------------------------------------------------

    def _get_check_connection(self, **_: Any) -> dict:
        return {"connected": True}

    def _get_list_open_programs(self, **_: Any) -> dict:
        return {"programs": [{"path": PROGRAM, "name": "Fake.dll"}], "count": 1}

    def _get_search_functions_by_tag(self, tag: str = "", **_: Any) -> dict:
        addrs = self.tags.get(tag, [])
        by_addr = {f["address"]: f["name"] for f in self.functions}
        return {
            "functions": [{"address": a, "name": by_addr.get(a, "?")} for a in addrs],
            "count": len(addrs),
        }

    def _get_list_functions(self, **_: Any) -> Any:
        if self.drop_envelope:
            return "\n".join(f"{f['name']} at {f['address']}" for f in self.functions)
        return {"functions": list(self.functions), "count": len(self.functions),
                "total": len(self.functions)}

    def _get_list_globals(self, **_: Any) -> Any:
        if self.drop_envelope:
            return "\n".join(self.globals)
        return {"globals": list(self.globals), "count": len(self.globals),
                "total": len(self.globals)}

    def _get_list_segments(self, **_: Any) -> dict:
        return {"segments": list(self.segments), "count": len(self.segments)}

    def _get_list_shadowed_globals(self, **_: Any) -> dict:
        """Globals swallowed by a neighbouring data unit.

        Modelled as EMPTY by default rather than omitted: the fixture binary has
        no overlapping data, so "no shadowed globals" is the honest answer for it.
        The distinction that matters to the panel is empty-and-known vs
        unreadable, and `shadowed_globals` only degrades on OSError -- so leaving
        this unmodelled made the route 500 rather than report a clean binary.
        Set `self.shadowed` to exercise the populated path.
        """
        rows = list(getattr(self, "shadowed", ()) or ())
        return {"shadowed": rows, "count": len(rows), "total": len(rows)}

    def _get_list_properties(self, map: str = "", **_: Any) -> dict:  # noqa: A002
        entries = self.properties.get(map, {})
        return {"entries": [{"address": a, "value": v} for a, v in entries.items()],
                "count": len(entries)}

    def _get_get_property(self, map: str = "", address: str = "", **_: Any) -> dict:  # noqa: A002
        return {"value": self.properties.get(map, {}).get(str(address).replace("0x", ""))}

    def _get_get_program_options(self, **_: Any) -> dict:
        return {"options": [{"name": k, "value": v} for k, v in self.program_options.items()]}

    def _get_get_function_tags(self, address: str = "", **_: Any) -> dict:
        a = str(address).replace("0x", "").lower()
        return {"tags": [t for t, addrs in self.tags.items() if a in addrs]}

    def _get_get_function_signature(self, address: str = "", **_: Any) -> dict:
        a = str(address).replace("0x", "").lower()
        name = next((f["name"] for f in self.functions if f["address"] == a), "FUN_%s" % a)
        return {"signature": f"int __stdcall {name}(int param_1)", "name": name}

    def _get_decompile_function(self, address: str = "", **_: Any) -> dict:
        a = str(address).replace("0x", "").lower()
        name = next((f["name"] for f in self.functions if f["address"] == a), "FUN_%s" % a)
        return {"decompilation": f"int {name}(int param_1)\n{{\n  return param_1;\n}}\n"}

    def _get_list_bookmarks(self, **_: Any) -> dict:
        return {"bookmarks": [], "count": 0}

    def _get_server_checkouts(self, **_: Any) -> dict:
        # Shared-server checkout state. Empty is the honest answer for a
        # local, non-shared project.
        return {"checkouts": [], "count": 0}


#: What a fully-deployed plugin reports. `endpoint_contract` bypasses `_get`
#: and drives urllib itself, so it needs its own stub or the tier makes a real
#: network call to the operator's Ghidra at import of `conformance_api`.
CONTRACT_OK = {
    "missing": [],
    "optional_missing": [],
    "unreachable": False,
    "present": [],
}


def install(monkeypatch, fake: "FakeGhidra | None" = None) -> "FakeGhidra":
    """Point ``conformance_dashboard`` at the fake and return it.

    Patches:

    ``_get`` / ``_post``    the only two transport functions the read layer
                            uses.
    ``PROGRAM``             so a route that forgets ``program=`` lands on the
                            fake rather than reaching for the operator's real
                            D2Common.
    ``endpoint_contract``   drives ``urllib`` directly rather than going
                            through ``_get``, and ``conformance_api`` calls it
                            from a daemon thread AT IMPORT. Unpatched, merely
                            building the app makes 19 real HTTP requests to
                            127.0.0.1:8089.
    ``GHIDRA``              a deliberately unroutable URL, so anything this
                            fake failed to model fails fast and loudly instead
                            of quietly succeeding against the real plugin.
    """
    import conformance_dashboard as cd

    fake = fake or FakeGhidra()
    monkeypatch.setattr(cd, "_get", fake.get)
    monkeypatch.setattr(cd, "_post", fake.post)
    monkeypatch.setattr(cd, "PROGRAM", PROGRAM)
    monkeypatch.setattr(cd, "endpoint_contract", lambda: dict(CONTRACT_OK))
    monkeypatch.setattr(cd, "GHIDRA", "http://127.0.0.1:1", raising=False)
    return fake
