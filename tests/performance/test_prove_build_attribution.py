"""Coverage for live-prove ABI detection and shared-build failure attribution.

All of this comes from one measurement (2026-07-31) over 523 terminal
`live_prove_failed` rows. Only 78 (15%) were genuine semantic mismatches:

    152  marshal_fault / SEH          <- ABI, 79% of them cdecl-declared-stdcall
    126  unresolved sym from ANOTHER candidate   <- COLLATERAL
     78  semantic mismatch            <- the only real verdicts
     58  compile error                <- genuinely the draft's own
     37  unresolved sym in own draft  <- genuinely the draft's own
     24  duplicate symbol (collateral)

`live_prove_failed` is TERMINAL, so every collateral row permanently retired a
function whose reimpl compiled fine and never executed once.
"""

import os
import sys
import time
from pathlib import Path

import pytest

FUN_DOC = Path(__file__).resolve().parents[2] / "fun-doc"
if str(FUN_DOC) not in sys.path:
    sys.path.insert(0, str(FUN_DOC))

plp = pytest.importorskip("port_live_prove")


# ======================================================= symbol undecoration ==

@pytest.mark.parametrize("sym,expected", [
    ("_Foo@8", "Foo"),                                  # stdcall
    ("_Foo", "Foo"),                                    # cdecl
    ("@Foo@4", "Foo"),                                  # FASTCALL - leading @
    ("?Foo@@YGHPAXH0@Z", "Foo"),                        # C++ mangled
    ('"int __stdcall Foo(void *,int)"', "Foo"),         # undecorated, quoted
    ("_BINKW32_ProcessFrameWriteAsync@4", "BINKW32_ProcessFrameWriteAsync"),
])
def test_undecorate(sym, expected):
    assert plp._undecorate(sym) == expected


def test_fastcall_undecoration_does_not_yield_empty():
    """`@Foo@4`.split("@")[0] is the EMPTY STRING. Before the leading-@ strip,
    every fastcall referrer attributed to an offender named "" -- which then
    out-sorted every real candidate name and took the blame for 34 of 125
    collateral rows."""
    assert plp._undecorate("@LOOTFILTER_ResetFilterCtx@4") == "LOOTFILTER_ResetFilterCtx"
    assert plp._undecorate("@LOOTFILTER_ResetFilterCtx@4") != ""


# ================================================ unresolved-symbol attribution ==

_VCXPROJ = "[C:\\D2MOO\\build\\D2MOO_ReimplProvider.vcxproj]"


def _lnk2019(symbol, referrer):
    return (f"error LNK2019: unresolved external symbol {symbol} "
            f"referenced in function {referrer} {_VCXPROJ}")


def test_own_draft_unresolved_is_build_candidate():
    """`FlushFileDescriptor` really did reference an undefined `_GetDosErrnoPtr`
    from its OWN body. That stays the draft's problem and feeds the fix loop."""
    out = _lnk2019("_GetDosErrnoPtr", "_FlushFileDescriptor@4")
    stage, detail, quarantine = plp._find_unresolved_symbol_offender(
        out, "FlushFileDescriptor")
    assert stage == "build_candidate"
    assert quarantine is None


def test_sibling_unresolved_is_collateral(monkeypatch, tmp_path):
    """THE regression: `x_ismbbtype` was retired because
    `_BINK_CheckVideoFrameReady@4` was unresolved in
    `_BINKW32_ProcessFrameWriteAsync@4` -- a function it has nothing to do
    with."""
    monkeypatch.setattr(plp, "CANDIDATES_DIR", tmp_path)
    (tmp_path / "BINKW32_ProcessFrameWriteAsync.cpp").write_text("//", encoding="utf-8")
    out = _lnk2019("_BINK_CheckVideoFrameReady@4", "_BINKW32_ProcessFrameWriteAsync@4")
    stage, detail, quarantine = plp._find_unresolved_symbol_offender(out, "x_ismbbtype")
    assert stage == "build_provider_unresolved_symbol"
    assert quarantine == "BINKW32_ProcessFrameWriteAsync"
    assert "collateral" in detail


def test_own_fault_wins_over_a_sibling(monkeypatch, tmp_path):
    """If our own draft is also broken, healing a sibling would not make this
    candidate link. Fix ours first."""
    monkeypatch.setattr(plp, "CANDIDATES_DIR", tmp_path)
    (tmp_path / "Sibling.cpp").write_text("//", encoding="utf-8")
    out = _lnk2019("_A", "_Sibling@4") + "\n" + _lnk2019("_B", "_Mine@4")
    stage, _, quarantine = plp._find_unresolved_symbol_offender(out, "Mine")
    assert stage == "build_candidate"
    assert quarantine is None


def test_never_attributes_to_a_nonexistent_candidate_file(monkeypatch, tmp_path):
    """The referring function may live in provider RUNTIME code we must never
    touch. No candidate file, no attribution."""
    monkeypatch.setattr(plp, "CANDIDATES_DIR", tmp_path)
    out = _lnk2019("_Missing", "_SomeProviderRuntimeFn@4")
    assert plp._find_unresolved_symbol_offender(out, "Victim") is None


def test_no_link_error_is_not_attributed():
    assert plp._find_unresolved_symbol_offender("error C2065: undeclared", "Foo") is None


def test_unresolved_without_a_referrer_is_not_attributed(monkeypatch, tmp_path):
    monkeypatch.setattr(plp, "CANDIDATES_DIR", tmp_path)
    out = f"error LNK2019: unresolved external symbol _Orphan {_VCXPROJ}"
    assert plp._find_unresolved_symbol_offender(out, "Foo") is None


# ============================================================= callconv ABI ==

def _layout(n_stack_args, out=True):
    return {"inputs": [{"name": f"a{i}", "register": ""} for i in range(n_stack_args)],
            "outputs": [{"register": "EAX"}] if out else []}


def test_no_program_keeps_legacy_behaviour():
    """Without a program there is no disassembly to consult, and the old
    stdcall default must be preserved exactly."""
    spec = plp.translate_layout_to_spec("F", "0x1000", _layout(2))
    assert spec["callconv"] == "stdcall"
    assert "callconv_source" not in spec


def test_bare_ret_with_stack_args_becomes_cdecl(monkeypatch):
    """THE fix. A callee that does not pop, declared stdcall, means NOBODY
    cleans: D2Oracle_Call casts to the declared convention, so ESP leaks
    4*argc per call. 79% of marshal_fault functions end in a bare RET against
    41% of live-proven ones."""
    monkeypatch.setattr(plp, "detect_stack_cleanup", lambda p, a: 0)
    spec = plp.translate_layout_to_spec("F", "0x1000", _layout(2), program="/p/x.dll")
    assert spec["callconv"] == "cdecl"
    assert "bare RET" in spec["callconv_source"]


def test_matching_ret_width_stays_stdcall(monkeypatch):
    monkeypatch.setattr(plp, "detect_stack_cleanup", lambda p, a: 8)
    spec = plp.translate_layout_to_spec("F", "0x1000", _layout(2), program="/p/x.dll")
    assert spec["callconv"] == "stdcall"
    assert "callconv_source" not in spec


def test_arity_disagreement_is_refused(monkeypatch):
    """Calling with the wrong slot count on a callee-cleans convention skews
    ESP for the rest of the chain and access-violates the GAME (eip=0x140).
    An unsupported_abi verdict is strictly better than a crashed process."""
    monkeypatch.setattr(plp, "detect_stack_cleanup", lambda p, a: 16)   # 4 args
    with pytest.raises(plp.UnsupportedLiveABI) as e:
        plp.translate_layout_to_spec("F", "0x1000", _layout(1), program="/p/x.dll")
    assert "disassembly is the authority" in str(e.value)
    assert "4 stack argument" in str(e.value)


def test_zero_arg_bare_ret_stays_stdcall(monkeypatch):
    """A 0-arg stdcall also emits a bare RET -- there is nothing to clean, so
    the two conventions are indistinguishable AND equivalent. Must not be
    'corrected' to cdecl on no evidence."""
    monkeypatch.setattr(plp, "detect_stack_cleanup", lambda p, a: 0)
    spec = plp.translate_layout_to_spec("F", "0x1000", _layout(0), program="/p/x.dll")
    assert spec["callconv"] == "stdcall"


def test_undeterminable_cleanup_changes_nothing(monkeypatch):
    monkeypatch.setattr(plp, "detect_stack_cleanup", lambda p, a: None)
    spec = plp.translate_layout_to_spec("F", "0x1000", _layout(2), program="/p/x.dll")
    assert spec["callconv"] == "stdcall"


def test_register_explicit_path_skips_the_check(monkeypatch):
    """orig_regs calls the original through a hand-asm register stub with NO
    stack args, so the callee's RET width says nothing about our invocation."""
    called = []
    monkeypatch.setattr(plp, "detect_stack_cleanup",
                        lambda p, a: called.append(1) or 0)
    layout = {"inputs": [{"name": "n", "register": "ESI"}],
              "outputs": [{"register": "EAX"}]}
    spec = plp.translate_layout_to_spec("F", "0x1000", layout, program="/p/x.dll")
    assert spec.get("orig_regs")
    assert called == []


@pytest.mark.parametrize("cc,argc,expected", [
    ("stdcall", 0, 0), ("stdcall", 1, 4), ("stdcall", 3, 12),
    ("fastcall", 1, 0), ("fastcall", 2, 0), ("fastcall", 4, 8),
    ("thiscall", 3, 4), ("cdecl", 5, 0),
])
def test_expected_cleanup(cc, argc, expected):
    assert plp._expected_cleanup(cc, argc) == expected


def test_detect_stack_cleanup_parses_ret(monkeypatch):
    monkeypatch.setattr(plp, "_ghidra_get_json", lambda p: {"instructions": [
        {"instruction": "MOV EAX,dword ptr [ESP + 0x4]"},
        {"instruction": "RET 0x4"}]})
    assert plp.detect_stack_cleanup("/p/x.dll", "1000") == 4

    monkeypatch.setattr(plp, "_ghidra_get_json", lambda p: {"instructions": [
        {"instruction": "RET"}]})
    assert plp.detect_stack_cleanup("/p/x.dll", "1000") == 0


def test_detect_stack_cleanup_refuses_ambiguity(monkeypatch):
    """Disagreeing RETs, or none at all (tail-call JMP), mean we cannot claim
    to know the convention. Returning None leaves behaviour unchanged rather
    than guessing."""
    monkeypatch.setattr(plp, "_ghidra_get_json", lambda p: {"instructions": [
        {"instruction": "RET 0x4"}, {"instruction": "RET 0x8"}]})
    assert plp.detect_stack_cleanup("/p/x.dll", "1000") is None

    monkeypatch.setattr(plp, "_ghidra_get_json", lambda p: {"instructions": [
        {"instruction": "JMP dword ptr [EAX]"}]})
    assert plp.detect_stack_cleanup("/p/x.dll", "1000") is None


def test_detect_stack_cleanup_survives_unreachable_ghidra(monkeypatch):
    def boom(p):
        raise OSError("connection refused")
    monkeypatch.setattr(plp, "_ghidra_get_json", boom)
    assert plp.detect_stack_cleanup("/p/x.dll", "1000") is None


# =========================================================== in-flight guard ==

def test_inflight_own_claim_never_blocks_self(monkeypatch, tmp_path):
    monkeypatch.setattr(plp, "_INFLIGHT_DIR", tmp_path)
    plp.mark_candidate_inflight("Mine")
    assert "Mine" not in plp.inflight_candidates()


def test_inflight_protects_a_live_foreign_owner(monkeypatch, tmp_path):
    monkeypatch.setattr(plp, "_INFLIGHT_DIR", tmp_path)
    monkeypatch.setattr(plp, "_pid_alive", lambda pid: True)
    (tmp_path / "Theirs.inflight").write_text("4242", encoding="utf-8")
    assert "Theirs" in plp.inflight_candidates()


def test_inflight_prunes_a_dead_owner(monkeypatch, tmp_path):
    """A force-killed dashboard must never leave a broken candidate
    permanently un-healable."""
    monkeypatch.setattr(plp, "_INFLIGHT_DIR", tmp_path)
    monkeypatch.setattr(plp, "_pid_alive", lambda pid: False)
    marker = tmp_path / "Dead.inflight"
    marker.write_text("999999", encoding="utf-8")
    assert "Dead" not in plp.inflight_candidates()
    assert not marker.exists()


def test_inflight_expires_by_age(monkeypatch, tmp_path):
    """PID-liveness alone is not enough: the owner is a long-lived dashboard,
    so every marker it ever wrote would stay valid forever."""
    monkeypatch.setattr(plp, "_INFLIGHT_DIR", tmp_path)
    monkeypatch.setattr(plp, "_pid_alive", lambda pid: True)
    monkeypatch.setattr(plp, "_INFLIGHT_TTL_SEC", 60.0)
    marker = tmp_path / "Old.inflight"
    marker.write_text("4242", encoding="utf-8")
    old = time.time() - 3600
    os.utime(marker, (old, old))
    assert "Old" not in plp.inflight_candidates()
    assert not marker.exists()


def test_clear_removes_the_claim(monkeypatch, tmp_path):
    monkeypatch.setattr(plp, "_INFLIGHT_DIR", tmp_path)
    plp.mark_candidate_inflight("X")
    assert (tmp_path / "X.inflight").exists()
    plp.clear_candidate_inflight("X")
    assert not (tmp_path / "X.inflight").exists()


# ================================================ environmental classification ==

def test_collateral_build_stages_are_environmental():
    """Non-terminal, so the function is re-queued instead of retired for
    somebody else's defect. Same principle as bad_target."""
    from fun_doc import _prove_failure_is_environmental

    for stage in ("build_provider_unresolved_symbol",
                  "build_provider_duplicate_symbol",
                  "build_provider_cascade"):
        assert _prove_failure_is_environmental(stage) is True, stage


def test_own_build_failures_stay_terminal():
    """The deliberate asymmetry: build_candidate IS this draft's own compile
    error, and an unattributed build_provider is not evidence of anything."""
    from fun_doc import _prove_failure_is_environmental

    for stage in ("build_candidate", "build_provider", "mismatch", "marshal_fault"):
        assert _prove_failure_is_environmental(stage) is False, stage


def test_environmental_reason_is_honest_per_stage():
    """Every environmental re-queue used to record 'oracle down', which is
    false for a build cascade and sends the next reader to the game process."""
    from fun_doc import _environmental_reason

    reason = _environmental_reason("build_provider_unresolved_symbol", "")
    assert "oracle" not in reason.lower()
    assert "never executed" in reason


# =============================== callconv resolution is SHARED, not per-site ==

def test_resolve_callconv_is_used_by_every_spec_builder():
    """The fix that only lived in translate_layout_to_spec reached exactly ONE
    of 282 written specs while marshal_fault grew 152 -> 236 overnight: the
    synth/synth2/delegate paths each hardcoded `"callconv": "stdcall"`.

    Same failure CLAUDE.md records for `_write_spec` -- "five call sites once
    wrote their own, which is how four of five would miss a fix like this".
    """
    src = Path(plp.__file__).resolve().read_text(encoding="utf-8")
    # Prompt text may mention stdcall; a SPEC dict literal must not pin it.
    assert '"callconv": "stdcall",\n' not in src.replace(
        '            "callconv": "stdcall",\n', "", 1), (
        "a spec builder is hardcoding callconv again -- route it through "
        "resolve_callconv"
    )
    assert src.count("resolve_callconv(name, address, program") >= 3


@pytest.mark.parametrize("cleanup,argc,expected_cc", [
    (0, 1, "cdecl"),      # bare RET with a stack arg -> callee does not clean
    (4, 1, "stdcall"),    # matches
    (0, 0, "stdcall"),    # nothing to clean; conventions are equivalent
])
def test_resolve_callconv_decisions(monkeypatch, cleanup, argc, expected_cc):
    monkeypatch.setattr(plp, "detect_stack_cleanup", lambda p, a: cleanup)
    cc, _ = plp.resolve_callconv("F", "0x1000", "/p/x.dll", argc)
    assert cc == expected_cc


def test_resolve_callconv_warns_on_arity_mismatch(monkeypatch):
    """The probe builders use a fixed one-arg shape, so the honest signal is a
    warning plus an unchanged convention -- translate_layout_to_spec, which
    owns a real drafted layout, refuses outright instead."""
    monkeypatch.setattr(plp, "detect_stack_cleanup", lambda p, a: 8)
    cc, note = plp.resolve_callconv("F", "0x1000", "/p/x.dll", 1)
    assert cc == "stdcall"
    assert note and "arity mismatch" in note


def test_resolve_callconv_never_guesses(monkeypatch):
    """Unreadable or ambiguous disassembly must leave the caller exactly where
    it was -- never worse than the status quo."""
    monkeypatch.setattr(plp, "detect_stack_cleanup", lambda p, a: None)
    assert plp.resolve_callconv("F", "0x1000", "/p/x.dll", 1) == ("stdcall", None)
    assert plp.resolve_callconv("F", "0x1000", None, 1) == ("stdcall", None)
