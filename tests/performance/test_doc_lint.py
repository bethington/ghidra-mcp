"""Coverage for doc_lint's library/domain-prefix contradiction rule.

The rule exists because cross-version hash propagation spreads a name to every
binary with a matching function hash, and statically-linked CRT is identical
everywhere -- so one wrong name reaches the whole corpus. The cases below are
modelled on the measured PD2_EXT.dll finding (a `version.dll` proxy shim whose
CRT carries `DATATBLS_` / `COLLISION_` / `MONSTER_` names).

Offline: no Ghidra, no network. Only the pure classify/calibrate/find_defects
layer is exercised; the HTTP collection layer is I/O and is covered by running
the tool.
"""
import sys
from pathlib import Path

import pytest

FUN_DOC = Path(__file__).resolve().parents[2] / "fun-doc"
if str(FUN_DOC) not in sys.path:
    sys.path.insert(0, str(FUN_DOC))

dl = pytest.importorskip("doc_lint")


def _fn(name, addr="1000"):
    return {"name": name, "address": addr}


def _edge(caller, callee):
    return {"caller": caller, "callee": callee}


# ------------------------------------------------------------- helpers ------

def test_strip_ref_handles_address_and_module_qualifiers():
    assert dl.strip_ref("GAME_DllStartupInitialize@100012a3") == "GAME_DllStartupInitialize"
    assert dl.strip_ref("KERNEL32.DLL::VirtualProtect@EXTERNAL:0000000d") == "VirtualProtect"
    assert dl.strip_ref("") == ""


def test_module_prefix_extraction():
    assert dl.module_prefix("DATATBLS_SortElements") == "DATATBLS"
    assert dl.module_prefix("D2CLIENT_DrawUnit") == "D2CLIENT"
    # PascalCase without a prefix, and lowercase CRT names, have none.
    assert dl.module_prefix("ApplyCodePatch") is None
    assert dl.module_prefix("__scrt_dllmain_crt_thread_attach") is None
    assert dl.module_prefix("") is None


# ------------------------------------------------------- classification -----

def test_renamed_crt_is_still_caught_via_callees():
    """The whole point: renaming destroys the NAME signal, not the callee one.

    `DATATBLS_SortElements` matches no CRT name pattern -- it is only
    recognisable as runtime code because it calls __SEH_prolog4.
    """
    recs = dl.classify(
        [_fn("DATATBLS_SortElements")],
        [_edge("DATATBLS_SortElements", "__SEH_prolog4@10001c10")],
    )
    assert recs[0].is_library, "callee evidence must survive a rename"
    assert recs[0].prefix == "DATATBLS"


def test_lib_tag_alone_classifies():
    recs = dl.classify([_fn("MONSTER_SetupStateContext")], [],
                       lib_tagged=["MONSTER_SetupStateContext"])
    assert recs[0].is_library
    assert recs[0].library_reason == "LIB_tag"


def test_plain_game_function_is_not_library():
    recs = dl.classify(
        [_fn("D2CLIENT_DrawUnit")],
        [_edge("D2CLIENT_DrawUnit", "D2CLIENT_GetUnitX@6faa0000")],
    )
    assert not recs[0].is_library


# --------------------------------------------------------- calibration ------

def _corpus(domain_uses=30, crt_uses=30):
    """DATATBLS_ used mostly on real code; CRT_ used only on runtime code."""
    fns, edges = [], []
    for i in range(domain_uses):
        n = f"DATATBLS_RealTableFunc{i}"
        fns.append(_fn(n, f"{i:08x}"))
        edges.append(_edge(n, f"DATATBLS_Helper{i}@1000"))
    for i in range(crt_uses):
        n = f"CRT_RuntimeHelper{i}"
        fns.append(_fn(n, f"{i+1000:08x}"))
        edges.append(_edge(n, "__SEH_prolog4@10001c10"))
    return fns, edges


def test_calibration_separates_domain_from_runtime_prefixes():
    recs = dl.classify(*_corpus())
    stats = dl.calibrate(recs)
    assert stats["DATATBLS"]["is_domain"] is True
    assert stats["CRT"]["is_domain"] is False, "CRT_ is legitimate on runtime code"


def test_low_support_prefix_is_not_judged():
    """A prefix seen a handful of times must not calibrate itself into an
    exemption -- that is how a real defect class hides."""
    fns = [_fn(f"RARE_Thing{i}", f"{i:08x}") for i in range(3)]
    edges = [_edge(f"RARE_Thing{i}", "__SEH_prolog4@10001c10") for i in range(3)]
    stats = dl.calibrate(dl.classify(fns, edges))
    assert stats["RARE"]["total"] < dl.MIN_PREFIX_SUPPORT
    assert stats["RARE"]["is_domain"] is False


# ------------------------------------------------------------- defects ------

def test_the_pd2_ext_shape_is_flagged():
    """CRT function wearing a domain prefix -> defect. Runtime prefix -> not."""
    fns, edges = _corpus()
    # The contaminated one: CRT body, gameplay prefix.
    fns.append(_fn("DATATBLS_SortElements", "10008e90"))
    edges.append(_edge("DATATBLS_SortElements", "__SEH_prolog4@10001c10"))

    recs = dl.classify(fns, edges)
    stats = dl.calibrate(recs)
    defects = dl.find_defects(recs, stats)

    names = {d.name for d in defects}
    assert "DATATBLS_SortElements" in names
    assert not any(n.startswith("CRT_") for n in names), \
        "CRT_ on runtime code is correct naming, not a defect"


def test_non_library_domain_function_is_never_a_defect():
    fns, edges = _corpus()
    recs = dl.classify(fns, edges)
    stats = dl.calibrate(recs)
    defects = dl.find_defects(recs, stats)
    assert defects == [], "clean corpus must produce zero findings"
