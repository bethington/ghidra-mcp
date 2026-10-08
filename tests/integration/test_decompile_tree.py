"""
Live integration tests for the decompilation tree.

Creates trees only under pytest ``tmp_path`` roots and always deletes with
``delete_files=true`` so nothing is left under ``/tmp/ghidra-mcp-tree``.

Skips cleanly (does not fail) when Ghidra is down or tree endpoints are
absent from ``/mcp/schema`` — the offline suite must stay green without a
server. Picks the smallest open program at runtime; skips if it exceeds
``MAX_FUNCTIONS_FOR_LIVE`` so this can never become a 10-minute ``ls`` sweep.

``program`` and other non-BODY params are ParamSource.QUERY — they go in the
URL query string, not the JSON body, or the endpoint silently targets the
CURRENT program.
"""

from __future__ import annotations

import hashlib
import re
import shutil
import time
from pathlib import Path
from urllib.parse import urlencode

import pytest
import requests

# Above this, a full sweep is too expensive for CI/dev loops (ls ≈ 25k).
MAX_FUNCTIONS_FOR_LIVE = 1000
# firmware_reconstructed.bin is ~4 s; give headroom for a loaded machine.
SWEEP_TIMEOUT_S = 120
POLL_INTERVAL_S = 0.15

pytestmark = [
    pytest.mark.integration,
    pytest.mark.usefixtures("require_server_and_checkout"),
]


@pytest.fixture(scope="module")
def require_server_and_checkout(server_available, server_url):
    """Skip the module when Ghidra is down or tree tools are undeployed."""
    if not server_available:
        pytest.skip(
            "MCP server is not running (start with Tools → GhidraMCP → Start MCP Server)"
        )
    try:
        resp = requests.get(f"{server_url}/mcp/schema", timeout=10)
    except requests.RequestException as exc:
        pytest.skip(f"Could not fetch /mcp/schema: {exc}")
    if resp.status_code != 200:
        pytest.skip(f"/mcp/schema returned {resp.status_code}")
    try:
        schema = resp.json()
    except ValueError:
        pytest.skip("/mcp/schema was not JSON")
    tools = schema.get("tools") or []
    paths = {
        (t.get("path") or t.get("name") or "")
        for t in tools
        if isinstance(t, dict)
    }
    required = {
        "/decompile_tree_create",
        "/decompile_tree_run",
        "/decompile_tree_status",
        "/decompile_tree_delete",
        "/decompile_tree_refresh",
    }
    missing = sorted(required - paths)
    if missing:
        pytest.skip(
            "tree endpoints absent from /mcp/schema (older JAR?): "
            + ", ".join(missing)
        )


@pytest.fixture(scope="module")
def smallest_program(server_url):
    """Smallest open program by function_count; never hardcode a specimen name."""
    resp = requests.get(f"{server_url}/list_open_programs", timeout=15)
    if resp.status_code != 200:
        pytest.skip(f"list_open_programs failed: {resp.status_code}")
    programs = resp.json().get("programs") or []
    if not programs:
        pytest.skip("No programs open in Ghidra")
    ranked = sorted(
        programs,
        key=lambda p: int(p.get("function_count") or 10**9),
    )
    chosen = ranked[0]
    count = int(chosen.get("function_count") or 0)
    if count <= 0:
        pytest.skip(f"Smallest program has no functions: {chosen.get('name')}")
    if count > MAX_FUNCTIONS_FOR_LIVE:
        pytest.skip(
            f"Smallest open program {chosen.get('name')!r} has {count} functions "
            f"(>{MAX_FUNCTIONS_FOR_LIVE}); refusing a live tree sweep"
        )
    return {
        "name": chosen["name"],
        "path": chosen.get("path") or chosen["name"],
        "function_count": count,
    }


def _post_json(http_client, path, *, params=None, body=None, timeout=None):
    """POST JSON with QUERY params in the URL (HttpClient.post has no params=)."""
    url = path
    if params:
        url = f"{path}?{urlencode(params)}"
    return http_client.post(url, json_data=body or {}, timeout=timeout)


def _get_json(http_client, path, *, params=None, timeout=None):
    resp = http_client.get(path, params=params, timeout=timeout)
    assert resp.status_code == 200, f"{path} -> {resp.status_code}: {resp.text[:300]}"
    return resp.json()


def _create(http_client, program_name, root: Path, **body_extra):
    body = {"root": str(root.resolve()), **body_extra}
    resp = _post_json(
        http_client,
        "/decompile_tree_create",
        params={"program": program_name},
        body=body,
    )
    assert resp.status_code == 200, resp.text[:500]
    data = resp.json()
    assert "error" not in data, data
    return data


def _delete(http_client, tree_id, *, delete_files=True):
    resp = _post_json(
        http_client,
        "/decompile_tree_delete",
        body={"tree": tree_id, "delete_files": delete_files},
    )
    # Already-gone is fine during teardown.
    if resp.status_code != 200:
        return
    try:
        data = resp.json()
    except ValueError:
        return
    if data.get("error"):
        return


def _status(http_client, tree_id):
    return _get_json(http_client, "/decompile_tree_status", params={"tree": tree_id})


def _start(http_client, tree_id):
    resp = _post_json(
        http_client, "/decompile_tree_run", body={"tree": tree_id, "action": "start"}
    )
    assert resp.status_code == 200, resp.text[:500]
    data = resp.json()
    assert "error" not in data, data
    return data


def _stop(http_client, tree_id):
    resp = _post_json(
        http_client, "/decompile_tree_run", body={"tree": tree_id, "action": "stop"}
    )
    assert resp.status_code == 200, resp.text[:500]
    data = resp.json()
    assert "error" not in data, data
    return data


def _poll_until(http_client, tree_id, *, predicate, timeout_s=SWEEP_TIMEOUT_S):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = _status(http_client, tree_id)
        if predicate(last):
            return last
        time.sleep(POLL_INTERVAL_S)
    raise AssertionError(
        f"timed out after {timeout_s}s waiting on {tree_id}; last={last}"
    )


def _read_status_md(root: Path) -> dict[str, str]:
    text = (root / "STATUS.md").read_text(encoding="utf-8")
    out = {}
    for line in text.splitlines():
        if ":" in line and not line.startswith("#"):
            key, _, val = line.partition(":")
            out[key.strip()] = val.strip()
    return out


def _c_files(root: Path) -> list[Path]:
    return sorted(root.rglob("*.c"))


def _fn_blocks(text: str) -> list[tuple[str, ...]]:
    """Return (name, addr, uri_addr) for each block header in a .c file."""
    lines = text.splitlines()
    blocks = []
    i = 0
    while i < len(lines):
        if lines[i].startswith("// fn: "):
            header = lines[i : i + 9]
            assert len(header) == 9, (
                f"block header must be exactly 9 lines, got {len(header)} "
                f"starting at line {i + 1}: {header!r}"
            )
            assert header[1].startswith("// calls:"), header[1]
            assert header[2].startswith("// callers:"), header[2]
            fn_m = re.match(r"^// fn: (.+) @ ([0-9A-Fa-f]+) size=", header[0])
            uri_m = re.match(r"^// uri: ghidra://function/[^/]+/([0-9A-Fa-f]+)$", header[7])
            assert fn_m, f"bad // fn: line: {header[0]!r}"
            assert uri_m, f"bad // uri: line (expected index 7 of 9): {header[7]!r}"
            assert header[7].startswith("// uri: ghidra://function/"), header[7]
            blocks.append((fn_m.group(1), fn_m.group(2), uri_m.group(1)))
            i += 9
        else:
            i += 1
    return blocks


def _file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


def _hash_c_tree(root: Path) -> dict[str, str]:
    return {
        str(p.relative_to(root)): _file_sha256(p)
        for p in _c_files(root)
    }


@pytest.fixture
def checkout_root(tmp_path):
    """Absolute empty root under pytest's tmp — never the default /tmp parent."""
    root = tmp_path / "tree"
    root.mkdir()
    return root


@pytest.fixture
def managed_checkout(http_client, smallest_program, checkout_root):
    """Create a tree and guarantee delete_files teardown."""
    created = _create(http_client, smallest_program["name"], checkout_root)
    tree_id = created["tree_id"]
    state = {"id": tree_id, "created": created, "rename": None}
    try:
        yield state
    finally:
        rename = state.get("rename")
        if rename:
            # Revert program mutation from the refresh case before dropping the tree.
            try:
                _post_json(
                    http_client,
                    "/rename_function",
                    params={"program": smallest_program["name"]},
                    body={
                        "old_name": rename["address"],
                        "new_name": rename["original_name"],
                        "strict_mode": "off",
                    },
                )
            except Exception:
                pass
        try:
            st = _status(http_client, tree_id)
            if st.get("phase") in {
                "queued",
                "waiting_for_analysis",
                "partitioning",
                "decompiling",
            }:
                _stop(http_client, tree_id)
        except Exception:
            pass
        _delete(http_client, tree_id, delete_files=True)
        if checkout_root.exists():
            shutil.rmtree(checkout_root, ignore_errors=True)


class TestDecompTreeLifecycle:
    def test_create_adopt_sweep_tree_invariants(
        self, http_client, smallest_program, managed_checkout, checkout_root
    ):
        """a–h: create/adopt identity, full sweep, tree + STATUS.md invariants."""
        created = managed_checkout["created"]
        tree_id = managed_checkout["id"]
        program = smallest_program["name"]

        # a. create → idle, adopted false, tree.json + STATUS.md on disk
        assert created["phase"] == "idle"
        assert created["adopted"] is False
        assert (checkout_root / "tree.json").is_file()
        assert (checkout_root / "STATUS.md").is_file()
        assert _read_status_md(checkout_root).get("state") == "empty"

        # b. create again → SAME id, adopted true (derived identity; duplicate
        # ids for one tree was a measured bug: tree_7de33ad7 vs tree_adeb2a7d)
        again = _create(http_client, program, checkout_root)
        assert again["tree_id"] == tree_id
        assert again["adopted"] is True

        # c. start → poll to complete
        _start(http_client, tree_id)
        final = _poll_until(
            http_client,
            tree_id,
            predicate=lambda s: s.get("phase") in {"complete", "failed", "cancelled"},
        )
        assert final["phase"] == "complete", final
        functions_done = int(final["functions_done"])
        assert functions_done > 0

        # d. .c files exist; every by-address row's function appears in its file;
        # row count == functions_done + 1 header
        c_files = _c_files(checkout_root)
        assert len(c_files) > 0
        tsv_path = checkout_root / "index" / "by-address.tsv"
        assert tsv_path.is_file()
        tsv_lines = tsv_path.read_text(encoding="utf-8").splitlines()
        assert len(tsv_lines) == functions_done + 1
        assert tsv_lines[0].startswith("address\tname\t")
        for row in tsv_lines[1:]:
            cols = row.split("\t")
            assert len(cols) >= 4, row
            addr, name, _part, rel = cols[0], cols[1], cols[2], cols[3]
            target = checkout_root / rel
            assert target.is_file(), f"missing {rel} for {name}@{addr}"
            body = target.read_text(encoding="utf-8", errors="replace")
            assert f"// fn: {name} @ {addr}" in body, (
                f"{name}@{addr} not found in {rel}"
            )

        # e. every .c file ≤ max_file_bytes, except a single oversized function
        max_bytes = int(final["config"]["max_file_bytes"])
        for path in c_files:
            size = path.stat().st_size
            if size <= max_bytes:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
            n_fns = text.count("\n// fn: ") + (1 if text.startswith("// fn: ") else 0)
            assert n_fns == 1, (
                f"{path.relative_to(checkout_root)} is {size} bytes "
                f"(>{max_bytes}) but holds {n_fns} functions — only a single "
                f"oversized function may exceed the budget"
            )

        # f. every block header is 9 lines; uri address matches // fn: address
        for path in c_files:
            text = path.read_text(encoding="utf-8", errors="replace")
            for name, addr, uri_addr in _fn_blocks(text):
                assert addr.lower() == uri_addr.lower(), (
                    f"{path.name}: fn addr {addr} != uri addr {uri_addr} ({name})"
                )
                assert f"ghidra://function/" in text

        # g. STATUS.md state: clean
        status_md = _read_status_md(checkout_root)
        assert status_md.get("state") == "clean", status_md
        assert final.get("status_state") == "clean"

        # h. no stray *.tmp anywhere in the tree
        tmps = list(checkout_root.rglob("*.tmp"))
        assert tmps == [], f"stray tmp files: {tmps}"


class TestDecompTreeCancellation:
    def test_stop_mid_sweep(
        self, http_client, smallest_program, managed_checkout, checkout_root
    ):
        """i. stop after progress: phase cancelled, STATUS cancelled, no *.tmp."""
        tree_id = managed_checkout["id"]
        _start(http_client, tree_id)
        _poll_until(
            http_client,
            tree_id,
            predicate=lambda s: int(s.get("functions_done") or 0) > 0
            or s.get("phase") in {"complete", "failed", "cancelled"},
            timeout_s=SWEEP_TIMEOUT_S,
        )
        # If the sweep finished before we could stop, restart once — the
        # cancel path is what this case pins, not a race with a tiny binary.
        st = _status(http_client, tree_id)
        if st.get("phase") == "complete":
            _start(http_client, tree_id)
            _poll_until(
                http_client,
                tree_id,
                predicate=lambda s: int(s.get("functions_done") or 0) > 0
                or s.get("phase") in {"complete", "failed", "cancelled"},
            )
        _stop(http_client, tree_id)
        stopped = _poll_until(
            http_client,
            tree_id,
            predicate=lambda s: s.get("phase") in {"cancelled", "complete", "failed"},
            timeout_s=30,
        )
        assert stopped["phase"] == "cancelled", stopped
        assert _read_status_md(checkout_root).get("state") == "cancelled"
        assert list(checkout_root.rglob("*.tmp")) == []


class TestTreeRootRecreate:
    def test_root_vanishes_mid_sweep(
        self, http_client, smallest_program, managed_checkout, checkout_root
    ):
        """j. Ghidra's temp dir was deleted under a live process — recreate must show."""
        tree_id = managed_checkout["id"]
        _start(http_client, tree_id)
        _poll_until(
            http_client,
            tree_id,
            predicate=lambda s: int(s.get("functions_done") or 0) > 0
            or s.get("phase") in {"complete", "failed", "cancelled"},
        )
        st = _status(http_client, tree_id)
        if st.get("phase") == "complete":
            # Tiny/fast sweep finished before the delete window; restart so the
            # vanish happens while decompiling is still writing.
            _start(http_client, tree_id)
            time.sleep(0.2)

        assert checkout_root.exists()
        shutil.rmtree(checkout_root)

        final = _poll_until(
            http_client,
            tree_id,
            predicate=lambda s: s.get("phase") in {"complete", "failed", "cancelled"},
        )
        assert final["phase"] == "complete", final
        assert int(final.get("root_recreated") or 0) >= 1, final
        assert checkout_root.is_dir()
        assert (checkout_root / "STATUS.md").is_file()


class TestDecompTreeRefresh:
    def test_refresh_rewrites_only_blast_radius_files(
        self, http_client, smallest_program, managed_checkout, checkout_root
    ):
        """k. rename + refresh target/callers: only those files change; TSV name updates."""
        tree_id = managed_checkout["id"]
        program = smallest_program["name"]

        _start(http_client, tree_id)
        final = _poll_until(
            http_client,
            tree_id,
            predicate=lambda s: s.get("phase") in {"complete", "failed", "cancelled"},
        )
        assert final["phase"] == "complete", final

        # Prefer a function that actually has callers so the blast radius is >1.
        listed = _get_json(
            http_client,
            "/find_functions",
            params={"program": program, "limit": 80},
        )
        target = None
        callers = []
        for fn in listed.get("functions") or []:
            addr_q = fn["address"]
            cre = _get_json(
                http_client,
                "/get_functions",
                params={
                    "function": addr_q,
                    "program": program,
                    "fields": "callers",
                    "include_call_context": "false",
                },
            )
            got = cre.get("callers") or []
            if got:
                target = fn
                callers = got
                break
        if target is None:
            pytest.skip("No function with callers in the smallest program")

        target_addr = target["address"]
        original_name = target["name"]
        new_name = "DecompTreeBlastRadiusProbe"
        affected_addrs = {target_addr.lower().removeprefix("0x")}
        for c in callers:
            affected_addrs.add(str(c["address"]).lower().removeprefix("0x"))

        tsv_path = checkout_root / "index" / "by-address.tsv"
        before_hashes = _hash_c_tree(checkout_root)
        before_tsv = tsv_path.read_text(encoding="utf-8")

        # Map addr → relative file from the index so we know which hashes may move.
        addr_to_file = {}
        for row in before_tsv.splitlines()[1:]:
            cols = row.split("\t")
            addr_to_file[cols[0].lower()] = cols[3]

        expected_changed = {
            addr_to_file[a]
            for a in affected_addrs
            if a in addr_to_file
        }
        assert expected_changed, "target/callers not present in by-address.tsv"

        rename_resp = _post_json(
            http_client,
            "/rename_function",
            params={"program": program},
            body={
                "old_name": target_addr,
                "new_name": new_name,
                "strict_mode": "off",
            },
        )
        assert rename_resp.status_code == 200, rename_resp.text[:400]
        rename_body = rename_resp.json()
        assert rename_body.get("status") != "rejected", rename_body
        managed_checkout["rename"] = {
            "address": target_addr,
            "original_name": original_name,
        }

        addr_csv = ",".join(
            sorted(
                {target_addr}
                | {c["address"] for c in callers}
            )
        )
        refresh = _post_json(
            http_client,
            "/decompile_tree_refresh",
            params={"program": program},
            body={"tree": tree_id, "addresses": addr_csv},
        )
        assert refresh.status_code == 200, refresh.text[:400]
        refresh_body = refresh.json()
        assert "error" not in refresh_body, refresh_body
        assert refresh_body.get("busy") is not True, refresh_body

        after_hashes = _hash_c_tree(checkout_root)
        changed = {
            rel
            for rel, digest in after_hashes.items()
            if before_hashes.get(rel) != digest
        }
        # New files should not appear; disappeared files count as changes too.
        changed |= set(before_hashes) ^ set(after_hashes)
        assert changed == expected_changed, (
            f"refresh dirty set {sorted(changed)} != expected {sorted(expected_changed)}"
        )

        after_tsv = tsv_path.read_text(encoding="utf-8")
        target_key = target_addr.lower().removeprefix("0x")
        name_updated = False
        for row in after_tsv.splitlines()[1:]:
            cols = row.split("\t")
            if cols[0].lower() == target_key:
                assert cols[1] == new_name, cols
                name_updated = True
                break
        assert name_updated, "by-address.tsv name column not updated for renamed target"

        # Revert immediately so a later failure in teardown is less likely to
        # leave the user's program renamed; fixture also reverts.
        revert = _post_json(
            http_client,
            "/rename_function",
            params={"program": program},
            body={
                "old_name": target_addr,
                "new_name": original_name,
                "strict_mode": "off",
            },
        )
        assert revert.status_code == 200, revert.text[:400]
        managed_checkout["rename"] = None
