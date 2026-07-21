"""type_unifier.py -- application-agnostic engine to collapse TWO overlapping C-type vocabularies
loaded in a Ghidra program into ONE name set.

Model: a PRIMARY (authoritative) source's type names win; a SECONDARY source BACKFILLS only the
types the primary lacks; a secondary struct that structurally DUPLICATES a primary struct (same
size, or exact size+field-offset signature) is deleted. Two guards keep it correct:
  * never_dedup(name) -- a category the secondary owns exclusively (the primary never defines it),
    so it is always backfill, never a size-coincidence duplicate.
  * dependency closure  -- a secondary helper a kept struct embeds/points to is retained even if it
    size-matches the primary, so the kept type graph resolves fully (no dangling references).

Nothing here is app-specific: sources are pluggable (TypeSource), the never-dedup category, the
program selector, and the marker name are all parameters. Diablo II / PD2 is one profile -- see
unify_types.py. Any application with two C-type corpora loaded into Ghidra can define its own.

Ghidra mechanics used (all generic): /import_data_types (CParser), /delete_data_type (cascades
references to `undefined`), /set_program_option + /save_program (a version marker), /list_open_programs.
"""
from __future__ import annotations

import hashlib
import json
import os
import urllib.parse
import urllib.request

GHIDRA = os.environ.get("GHIDRA_SERVER_URL", "http://127.0.0.1:8089").rstrip("/")


# ---- pluggable type source -------------------------------------------------------------------
class TypeSource:
    """A vocabulary of C types. Implement structs() and emit_header(); override deps() on the
    SECONDARY source so the engine can compute the dependency closure of the kept set.

    structs() -> {name: {"size": int|None, "fields": {offset:int -> {...}}}}
        `fields` is used only for its OFFSET SET (structural signature); a struct with no fields
        (forward-decl/opaque) is ignored by the dedup pass.
    emit_header() -> str        a CParser-clean header importable via /import_data_types.
    names()      -> set[str]     every type name this source defines (feeds the version marker).
    deps(name)   -> iterable     by-value + pointer type deps of `name` (secondary only; for closure).
    """

    def structs(self) -> dict:
        raise NotImplementedError

    def emit_header(self) -> str:
        raise NotImplementedError

    def names(self) -> set:
        return set(self.structs())

    def deps(self, name):
        return ()


class CallableTypeSource(TypeSource):
    """Adapter: wrap plain callables/dicts as a TypeSource without subclassing."""

    def __init__(self, structs, emit_header, names=None, deps=None):
        self._structs = structs
        self._emit = emit_header
        self._names = names
        self._deps = deps

    def structs(self):
        return self._structs() if callable(self._structs) else self._structs

    def emit_header(self):
        return self._emit() if callable(self._emit) else self._emit

    def names(self):
        if self._names is not None:
            return self._names() if callable(self._names) else self._names
        return super().names()

    def deps(self, name):
        return (self._deps(name) if self._deps else ()) or ()


def _sig(s):
    return (s.get("size"), tuple(sorted(s.get("fields", {}))))


def _added(res_text):
    try:
        return json.loads(res_text).get("types_added", 0) or 0
    except Exception:
        return 0


# ---- engine ----------------------------------------------------------------------------------
class Unifier:
    def __init__(self, primary: TypeSource, secondary: TypeSource, *, never_dedup=None,
                 program_selector=None, marker_group="Program Information",
                 marker_option="unified.types.version", ghidra=GHIDRA):
        self.primary = primary
        self.secondary = secondary
        self.never_dedup = never_dedup or (lambda _n: False)
        # program_selector(list_of_paths) -> filtered list; default keeps all
        self.program_selector = program_selector or (lambda paths: sorted(paths))
        self.marker_group = marker_group
        self.marker_option = marker_option
        self.ghidra = ghidra.rstrip("/")
        self._plan_cache = None

    # -- classification --------------------------------------------------------------------
    def plan(self):
        """(duplicates, keep): duplicates are SECONDARY structs to delete; keep is the backfill
        the secondary contributes (its non-duplicates + the dependency closure of that set)."""
        if self._plan_cache is not None:
            return self._plan_cache
        prim = self.primary.structs()
        sec = self.secondary.structs()
        prim_sigs = {_sig(s) for s in prim.values() if s.get("fields")}
        prim_sizes = {s.get("size") for s in prim.values() if s.get("fields") and s.get("size")}
        dup_cand, keep = set(), set()
        for n, s in sec.items():
            if not s.get("fields"):
                continue                      # opaque/forward-decl -> leave alone
            is_dup = (not self.never_dedup(n)) and (_sig(s) in prim_sigs or s.get("size") in prim_sizes)
            (dup_cand if is_dup else keep).add(n)
        # pull any dup that a kept struct depends on into keep, transitively (fixpoint)
        changed = True
        while changed:
            changed = False
            for n in list(keep):
                for dep in self.secondary.deps(n):
                    if dep in dup_cand:
                        dup_cand.discard(dep); keep.add(dep); changed = True
        self._plan_cache = (sorted(dup_cand), sorted(keep))
        return self._plan_cache

    def unified_marker(self):
        """Stable marker for 'the ONE unified set is loaded & current': uni1:<count>:<sha1_8> over
        (primary names + kept secondary names). Changes if either contribution changes."""
        names = sorted(self.primary.names() | set(self.plan()[1]))
        h = hashlib.sha1("\n".join(names).encode("utf-8")).hexdigest()[:8]
        return f"uni1:{len(names)}:{h}"

    # -- Ghidra I/O ------------------------------------------------------------------------
    def _post(self, path, body, program):
        url = f"{self.ghidra}{path}?program=" + urllib.parse.quote(program, safe="")
        req = urllib.request.Request(url, data=json.dumps(body).encode(),
                                     headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=300) as r:
            return r.read().decode("utf-8", "replace")

    def _get(self, path, **params):
        url = f"{self.ghidra}{path}" + ("?" + urllib.parse.urlencode(params) if params else "")
        with urllib.request.urlopen(url, timeout=60) as r:
            raw = r.read().decode("utf-8", "replace")
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return raw

    def open_programs(self):
        d = self._get("/list_open_programs")
        progs = d if isinstance(d, list) else d.get("programs", d.get("open_programs", []))
        out = [(p if isinstance(p, str) else (p.get("path") or p.get("name"))) for p in progs]
        return self.program_selector([p for p in out if p])

    # -- operations ------------------------------------------------------------------------
    def delete_dups(self, program, dups=None):
        """Delete each duplicate; a few passes handle type-graph reference ordering."""
        remaining = list(dups if dups is not None else self.plan()[0])
        deleted = 0
        for _pass in range(4):
            still = []
            for name in remaining:
                r = self._post("/delete_data_type", {"type_name": name}, program)
                if "deleted successfully" in r:
                    deleted += 1
                elif "not found" not in r.lower():
                    still.append(name)
            remaining = still
            if not remaining:
                break
        return {"program": program, "deleted": deleted, "left": len(remaining)}

    def reload_secondary(self, program):
        """Re-import the complete SECONDARY header (dependency-safe: its emit_header topo-sorts +
        forward-decls the whole set). Re-adds anything a prior over-delete removed."""
        return _added(self._post("/import_data_types", {"source": self.secondary.emit_header()}, program))

    def stamp(self, program):
        self._post("/set_program_option", {"group": self.marker_group,
                                           "name": self.marker_option,
                                           "value": self.unified_marker()}, program)

    def save(self, program):
        try:
            self._post("/save_program", {}, program)
        except Exception:
            pass

    def load_unified(self, program):
        """Idempotently bring ONE program to the unified set: import primary (base) + secondary,
        delete the duplicates, stamp the marker, save. Safe to re-run -- the delete pass runs every
        time, so it can NEVER re-introduce the secondary's duplicates."""
        dups, _keep = self.plan()
        added = 0
        for src in (self.primary, self.secondary):
            added += _added(self._post("/import_data_types", {"source": src.emit_header()}, program))
        self.delete_dups(program, dups)
        self.stamp(program)
        self.save(program)
        return {"program": program, "added": added, "deleted_dups": len(dups),
                "marker": self.unified_marker()}

    def restore(self, program):
        """Rebuild the unified state on a program that already has the primary loaded: reload the
        full secondary then delete the corrected dup set. (load_unified without re-importing primary.)"""
        added = self.reload_secondary(program)
        r = self.delete_dups(program)
        return {"program": program, "added": added, "deleted": r["deleted"], "left": r["left"]}
