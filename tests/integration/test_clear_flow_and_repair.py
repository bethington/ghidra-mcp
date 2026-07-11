"""
Integration tests for /clear_flow_and_repair.

Generic tests (TestValidation, TestRepairSmoke) run against any live server + program and do
not mutate program state beyond the repair itself.

Controlled tests (TestControlledRoundTrip) require a program containing the compute/helper
pair from the Task 4 test binary (cfr_target); they skip elsewhere. They prove the issue's
scenario end-to-end: a wrong no-return flag on the callee truncates the caller's flow on
repair, and correcting the flag + repairing twice more restores the exact baseline (against
this binary's topology, one post-reset repair converges only partway; see
TestControlledRoundTrip's docstring for why).
"""

import re

import pytest

pytestmark = [
    pytest.mark.integration,
    pytest.mark.usefixtures("require_server_and_program"),
]


@pytest.fixture(scope="module")
def require_server_and_program(server_available, program_loaded):
    if not server_available:
        pytest.skip("MCP server is not running")
    if not program_loaded:
        pytest.skip("No program loaded in Ghidra")


def addr_add(addr, delta):
    """Add delta to an address string, preserving any space prefix (split at the FINAL colon
    so overlay names containing punctuation survive)."""
    space, _, offset_str = addr.rpartition(":")
    offset = int(offset_str.removeprefix("0x"), 16)
    result = format(offset + delta, "x")
    return f"{space}:{result}" if space else f"0x{result}"


def repair(http_client, start, end=None):
    payload = {"start_address": start}
    if end is not None:
        payload["end_address"] = end
    return http_client.post("/clear_flow_and_repair", json_data=payload)


def function_body(http_client, address):
    """Return (body_min, body_max) parsed from /get_function_by_address, prefixes preserved."""
    r = http_client.get("/get_function_by_address", params={"address": address})
    m = re.search(r"Body:\s*(\S+)\s*-\s*(\S+)", r.text)
    if not m:
        pytest.skip(f"Cannot parse function body from: {r.text[:200]}")
    return m.group(1), m.group(2)


def find_function_by_name(http_client, name):
    """Entry address of a named function from /list_functions, or None."""
    r = http_client.get("/list_functions")
    if r.status_code != 200:
        return None
    m = re.search(rf"\b{re.escape(name)}\b\s+at\s+((?:\w+:)?(?:0x)?[0-9a-fA-F]+)", r.text)
    return m.group(1) if m else None


_DISASM_LINE_RE = re.compile(r"^([0-9a-fA-F]+):\s+(.*)$")


def disassemble_function(http_client, address):
    """Fetch a function's disassembly and parse it into (address, mnemonic-and-operands)
    tuples. Live format is e.g. "00101162: PUSH RBP" -- plain hex address, no 0x prefix."""
    r = http_client.get("/disassemble_function", params={"address": address})
    instructions = []
    for line in r.text.splitlines():
        m = _DISASM_LINE_RE.match(line.strip())
        if m:
            instructions.append((m.group(1), m.group(2)))
    return instructions


def _addr_value(addr):
    """Integer value of an address string, stripping an optional space prefix and 0x."""
    _, _, offset = addr.rpartition(":")
    return int(offset.removeprefix("0x"), 16)


@pytest.fixture
def any_function(http_client):
    """Entry address of any function, prefix preserved."""
    r = http_client.get("/list_functions")
    if r.status_code != 200:
        pytest.skip("Cannot list functions")
    m = re.search(r"at\s+((?:\w+:)?(?:0x)?[0-9a-fA-F]{4,})", r.text)
    if not m:
        pytest.skip("No functions found")
    return m.group(1)


class TestValidation:
    def test_missing_start_address_rejected(self, http_client):
        r = http_client.post("/clear_flow_and_repair", json_data={})
        assert "start_address parameter required" in r.text

    def test_end_equals_start_rejected(self, http_client, any_function):
        r = repair(http_client, any_function, any_function)
        assert "end_address must be greater than start_address" in r.text

    def test_end_before_start_rejected(self, http_client, any_function):
        r = repair(http_client, any_function, addr_add(any_function, -4))
        assert "end_address must be greater than start_address" in r.text


class TestRepairSmoke:
    """Weak assertions only: arbitrary programs may contain malformed flow, so repair may
    legitimately change counts. A full-body repair is deliberately NOT exercised here -- it
    can clear otherwise-healthy flow (see TestControlledRoundTrip's docstring), and this tier
    runs against whatever program happens to be loaded, so full-body coverage (and the
    success-payload shape it would assert) lives only in the controlled round trip below,
    where the target function and its flow topology are known."""

    def test_single_address_seed(self, http_client, any_function):
        r = repair(http_client, any_function)
        assert r.status_code == 200, r.text
        data = r.json()
        assert data["success"] is True
        assert data["repair"] is True
        assert data["clear_data"] is False
        assert data["clear_labels"] is False
        assert data["seed_range"]["start_address"]


class TestControlledRoundTrip:
    """Deterministic proof against the Task 4 cfr_target binary (compute calls helper,
    -O0 -fno-inline, helper genuinely returns so restoring no_return=False is correct).

    This endpoint is NOT a safe idempotent "repair a healthy function" operation: Ghidra's
    ClearFlowAndRepairCmd does not directly reseed an address that is a seed's sole candidate
    flow start (an instruction that is neither a function entry nor reached by fallthrough
    from inside the seed) -- but repair's disassembly follows flow transitively, so such an
    address can still get rebuilt if another retained/repaired path transitively reaches it.
    Whether healthy code survives a repair is therefore reachability-dependent, not guaranteed
    by "exactly one candidate": it can clear otherwise-healthy code, it does not always. The
    pristine full-body repair on compute's own baseline observably lost its back-edge-only
    loop body (22 instructions in the seed dropped to 14), because that repair left the loop
    body unreachable from any reseed point. That is why a pristine baseline can never come
    from a repair call here -- it must come from read endpoints only. This class proves the
    round trip: read the pristine state, damage it via a wrong no_return on helper, repair
    (which legitimately shrinks the seed because the call to helper no longer flows through),
    fix no_return, then repair TWICE more to restore the exact pristine baseline. Against this
    binary, one repair on the freshly-reset flag is itself another instance of the same
    reachability-dependent repair (compute -> 8 instructions, well short of the pristine 22);
    only a second repair on top of that -- now operating on flow the first repair already
    rebuilt -- fully re-converges to the pristine 22, byte-identical disassembly. Two
    applications are required for this controlled topology; do not generalize this to "repeat
    until converged" as a general recipe -- repair is not monotonic (it took the healthy
    22-instruction body down to 14 in the pristine characterization above), so more
    applications are not always better.
    """

    @pytest.fixture
    def compute_and_helper(self, http_client):
        compute = find_function_by_name(http_client, "compute")
        helper = find_function_by_name(http_client, "helper")
        if not compute or not helper:
            pytest.skip("Program does not contain the controlled compute/helper pair")
        return compute, helper

    def test_no_return_damage_then_restore(self, http_client, compute_and_helper):
        compute, helper = compute_and_helper
        body_min, body_max = function_body(http_client, compute)
        end_exclusive = addr_add(body_max, 1)

        # Pristine baseline comes from reads only -- see class docstring for why a repair
        # call cannot be used here.
        instructions = disassemble_function(http_client, compute)
        n_pristine = len(instructions)

        # Prove n_pristine is the complete function, not a truncated coincidence: a call to
        # helper is present, there is real code after that call, and the last instruction
        # sits at the function's own body_max (loop tail / RET).
        call_addr = None
        for addr, text in instructions:
            if text.startswith("CALL"):
                operand = text.split(maxsplit=1)[1].strip()
                try:
                    if _addr_value(operand) == _addr_value(helper):
                        call_addr = addr
                        break
                except ValueError:
                    # Indirect/register CALL operands (e.g. "CALL RAX") aren't hex
                    # addresses; they're real and expected here, not defensive noise.
                    continue
        assert call_addr is not None, "expected a CALL to helper in compute's disassembly"
        assert any(_addr_value(addr) > _addr_value(call_addr) for addr, _ in instructions), \
            "expected post-call code after the call to helper"
        # Compare by value, not text: /disassemble_function and /get_function_by_address
        # don't necessarily render the same address in the same textual form.
        assert _addr_value(instructions[-1][0]) == _addr_value(body_max)

        try:
            r = http_client.post("/set_function_no_return",
                                 json_data={"function_address": helper, "no_return": True})
            assert r.status_code == 200, r.text

            damaged = repair(http_client, body_min, end_exclusive).json()
            assert damaged["success"] is True
            # Flow stops at the call to the (wrongly) non-returning helper: strictly fewer
            # instructions in the seed. This is the evidence that the endpoint re-follows
            # flow rather than doing nothing.
            assert damaged["observations"]["instructions_in_seed_after"] < n_pristine
        finally:
            reset = http_client.post("/set_function_no_return",
                                     json_data={"function_address": helper, "no_return": False})
            # Load-bearing even though the repair calls below carry no assertions: an
            # unrestored flag poisons every later test against this program.
            assert reset.status_code == 200, reset.text
            # Best-effort cleanup/convergence, no assertions of any kind: a mid-test assertion
            # failure above must never be masked by a failure in this repair. Against this
            # binary this call is itself another instance of the same reachability-dependent
            # repair (see class docstring): it converges compute to 8 instructions, well short
            # of pristine. The second repair below -- outside try/finally, so it only runs on
            # the success path -- is the one that fully restores the baseline and carries the
            # restoration assertions.
            repair(http_client, body_min, end_exclusive)

        # Second post-reset repair over the same range: this is the one that actually
        # reconverges to the pristine baseline (see class docstring for why one isn't enough
        # against this binary's topology).
        restored = repair(http_client, body_min, end_exclusive)
        assert restored.status_code == 200, restored.text
        data = restored.json()
        assert data["success"] is True
        obs = data["observations"]
        assert obs["instructions_in_seed_after"] == n_pristine
        # Payload-shape assertions formerly covered by the deleted arbitrary-program
        # full-body smoke test; this full-body repair response is already in hand.
        functions_after = obs["functions_intersecting_seed_after"]
        assert isinstance(functions_after, list)
        assert any(f["name"] == "compute" for f in functions_after)
        # Semantic boundary check: the body max is back too, not just a coincidental count.
        _, body_max_restored = function_body(http_client, compute)
        assert body_max_restored == body_max
